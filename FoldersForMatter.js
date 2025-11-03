/**
 * Llama a la API para obtener la estructura de carpetas COMPLETA de un Matter.
 * @param {string} matterId El ID del Matter.
 * @return {Array<Object>} La lista PLANA de todas las carpetas.
 */
function apiGetFoldersForMatter_(matterId) {
  const url = `/api/matters/${encodeURIComponent(matterId)}/Documents/folders/tree`;
  log_('api.getFolders.url', url);
  try {
    const jsonResponse = mdGetJson_(url);
    log_('api.getFolders.response', { matterId: matterId, success: jsonResponse.success });
    return Array.isArray(jsonResponse?.data) ? jsonResponse.data : [];
  } catch (e) {
    log_('api.getFolders.error', String(e));
    return [];
  }
}

/**
 * Guarda el ID y el nombre de la carpeta de destino seleccionada en la caché.
 * @param {Object} folder - Un objeto con {id, name}.
 */
function saveDestinationFolderToCache_(folder) {
  try {
    CacheService.getUserCache().put('destination_folder', JSON.stringify(folder), 1800); // 30 min
    log_('cache.destination_folder_saved', folder);
  } catch (e) {
    log_('cache.destination_folder_save_error', { error: String(e) });
  }
}

/**
 * Lee la carpeta de destino seleccionada desde la caché.
 * @return {Object} El objeto con {id, name} o un objeto por defecto si no hay nada.
 */
function readDestinationFolderFromCache_() {
  try {
    const raw = CacheService.getUserCache().get('destination_folder');
    // El valor por defecto ahora incluye la ruta raíz.
    return raw ? JSON.parse(raw) : { id: null, name: "Matter Root", path: "/" };
  } catch (e) {
    log_('cache.destination_folder_read_error', { error: String(e) });
    return { id: null, name: "Matter Root", path: "/" };
  }
}

/**
 * Se ejecuta al hacer clic en "CHANGE".
 * ¡MODIFICADO! Ahora guarda la pantalla de origen en caché.
 */
function onSelectFolderClick_(e) {
  try {
    // ¡NUEVO! Leemos el parámetro 'origin' y lo guardamos
    const origin = e.parameters.origin || 'unknown';
    log_('onSelectFolderClick_.origin', { origin: origin });
    CacheService.getUserCache().put('folder_origin', origin, 1800); 

    const chosenMatter = readChosenMatterFromCache_();
    const allFolders = apiGetFoldersForMatter_(chosenMatter.id);
    if (!allFolders || allFolders.length === 0) return buildToast_("No folders found for this Matter.");
    
    CacheService.getUserCache().put('folder_list', JSON.stringify(allFolders), 1800);
    log_('cache_state.initial_save', { count: allFolders.length, hash: getListFingerprint_(allFolders) });

    const card = buildFolderTreeSelectionCard_(); 
    
    const nav = CardService.newNavigation().pushCard(card);
    return CardService.newActionResponseBuilder().setNavigation(nav).build();
  } catch (err) {
    log_('onSelectFolderClick_.error', String(err));
    return buildToast_(`Could not load folders: ${err.message}`);
  }
}

/**
 * Llama a la API para crear una nueva carpeta dentro de un Matter.
 * @param {string} matterId - El ID del Matter actual.
 * @param {string} folderName - El nombre para la nueva carpeta.
 * @param {string} parentId - El ID de la carpeta padre (puede ser null para la raíz).
 * @return {Object} La respuesta de la API.
 */
function apiCreateFolder_(matterId, folderName, parentId) {
  const url = `/api/matters/${encodeURIComponent(matterId)}/Documents/folder`;
  const payload = {
    name: folderName,
    parentId: parentId || "", // La API espera un string, aunque sea vacío.
    matterId: matterId // Aunque es redundante, lo incluimos como pide la especificación.
  };
  
  // El detalle clave: especificamos el Content-Type que tu API requiere.
  const options = {
    method: 'post',
    contentType: 'application/json-patch+json', // <-- ¡Importante!
    payload: JSON.stringify(payload)
  };

  const resp = callMaatdesk_(url, options);
  
  const responseCode = resp.getResponseCode();
  const responseText = resp.getContentText();

  if (responseCode >= 300) {
    throw new Error(`Create folder failed (${responseCode}): ${responseText}`);
  }
  
  log_('api.createFolder.success', { response: responseText });
  return JSON.parse(responseText || '{}');
}

/**
 * Se ejecuta cuando el usuario hace clic en el botón "Create New Folder".
 * Muestra el formulario para nombrar la nueva carpeta.
 */
function onCreateFolderClick_(e) {
  const currentFolderId = e.parameters.currentFolderId;
  const card = buildCreateFolderCard_(currentFolderId);
  const nav = CardService.newNavigation().pushCard(card);
  return CardService.newActionResponseBuilder().setNavigation(nav).build();
}

/**
 * Construye la tarjeta con el formulario para crear una nueva carpeta.
 * @param {string} parentId - El ID de la carpeta donde se creará la nueva.
 */
function buildCreateFolderCard_(parentId) {
  const b = CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader().setTitle("Create New Folder"));

  const section = CardService.newCardSection()
    .addWidget(CardService.newTextInput()
      .setFieldName("new_folder_name")
      .setTitle("Folder Name"));

  const buttonSet = CardService.newButtonSet()
    .addButton(CardService.newTextButton()
      .setText("Create")
      .setTextButtonStyle(CardService.TextButtonStyle.FILLED)
      .setBackgroundColor('#3ED79F')
      .setOnClickAction(CardService.newAction()
        .setFunctionName("onDoCreateFolder_")
        .setParameters({ parentId: parentId })))
    .addButton(CardService.newTextButton()
      .setText("Cancel")
      .setOnClickAction(CardService.newAction()
        .setFunctionName("onNavigateBack_"))
        .setTextButtonStyle(CardService.TextButtonStyle.TEXT)
        ); // onNavigateBack_ simplemente hace popCard()

  section.addWidget(buttonSet);
  b.addSection(section);
  return b.build();
}

/**
 * Se ejecuta al pulsar "Create". Llama a la API, refresca la lista y navega de vuelta.
 */
function onDoCreateFolder_(e) {
  try {
    const parentId = e.parameters.parentId;
    const newFolderName = e.formInput.new_folder_name;
    if (!newFolderName || newFolderName.trim().length === 0) return buildToast_("Folder name cannot be empty.");

    const oldFolders = JSON.parse(CacheService.getUserCache().get('folder_list') || '[]');
    log_('cache_state.before_create', { count: oldFolders.length, hash: getListFingerprint_(oldFolders) });

    const chosenMatter = readChosenMatterFromCache_();
    apiCreateFolder_(chosenMatter.id, newFolderName.trim(), parentId);
    
    // Utilities.sleep(1500); // Mantenemos la pausa por si acaso, pero el log es más importante.

    const newFolders = apiGetFoldersForMatter_(chosenMatter.id);
    CacheService.getUserCache().put('folder_list', JSON.stringify(newFolders), 1800);
    log_('cache_state.after_create_save', { count: newFolders.length, hash: getListFingerprint_(newFolders) });
    
    const card = buildFolderTreeSelectionCard_(parentId);
    const nav = CardService.newNavigation().updateCard(card);
    return CardService.newActionResponseBuilder().setNavigation(nav).build();
  } catch (err) {
    log_('onDoCreateFolder_.error', String(err));
    return buildToast_(`Error creating folder: ${err.message}`);
  }
}

/**
 * Se ejecuta cuando el usuario selecciona una carpeta de destino.
 * Guarda la elección en la caché y vuelve a la pantalla de previsualización.
 */
function onFolderSelected_(e) {
  try {
    const folder = {
      id: e.parameters.folderId,
      name: e.parameters.folderName
    };
    
    // Guardamos la carpeta seleccionada en la caché
    saveDestinationFolderToCache_(folder);
    
    // Usamos popCard() para volver a la pantalla anterior (la de previsualización)
    const nav = CardService.newNavigation().popCard();
    return CardService.newActionResponseBuilder().setNavigation(nav).build();
    
  } catch (err) {
    log_('onFolderSelected_.error', String(err));
    return buildToast_("Could not select the folder.");
  }
}

// ***** AÑADE ESTA FUNCIÓN A TU SCRIPT *****

/**
 * Construye y envía una petición multipart/form-data.
 * Este es el workaround para la limitación de UrlFetchApp.
 * @param {string} url El endpoint de la API.
 * @param {Object} metadata El objeto JSON para la parte 'json'.
 * @param {GoogleAppsScript.Base.Blob} fileBlob El archivo a subir.
 * @return {GoogleAppsScript.URL_Fetch.HTTPResponse} La respuesta del servidor.
 */
function uploadFileAsMultipart_(url, metadata, fileBlob) {
  const boundary = "------" + Utilities.computeDigest(Utilities.DigestAlgorithm.MD5, Math.random().toString()).map(b => (b+256).toString(16).padStart(2,'0')).join('');
  const at = getAccessTokenLax_();
  if (!at) throw new Error("AUTH_NO_TOKEN");

  // Construcción de la parte JSON
  let data = "--" + boundary + "\r\n";
  data += "Content-Disposition: form-data; name=\"json\"\r\n";
  data += "Content-Type: application/json\r\n\r\n";
  data += JSON.stringify(metadata) + "\r\n";

  // Construcción de la parte del archivo
  data += "--" + boundary + "\r\n";
  data += "Content-Disposition: form-data; name=\"file\"; filename=\"" + fileBlob.getName() + "\"\r\n";
  data += "Content-Type: " + fileBlob.getContentType() + "\r\n\r\n";

  // Unimos todo: JSON + bytes del archivo + cierre del boundary
  const payload = Utilities.newBlob(data).getBytes()
    .concat(fileBlob.getBytes())
    .concat(Utilities.newBlob("\r\n--" + boundary + "--").getBytes());

  const options = {
    method: "POST",
    contentType: "multipart/form-data; boundary=" + boundary,
    payload: payload,
    headers: { "Authorization": "Bearer " + at },
    muteHttpExceptions: true
  };

  return UrlFetchApp.fetch(url, options);
}

// Función de ayuda para el botón "Cancel"
function onNavigateBack_() {
  return CardService.newActionResponseBuilder()
    .setNavigation(CardService.newNavigation().popCard())
    .build();
}

/**
 * Construye la ruta de navegación (ej. /Emails/Drafts) para una carpeta dada.
 * @param {string} folderId - El ID de la carpeta final.
 * @param {Array<Object>} allFolders - La lista plana de todas las carpetas.
 * @return {string} La ruta completa como un string.
 */
function getFolderPath_(folderId, allFolders) {
  let path = [];
  let current = allFolders.find(f => f.id === folderId);
  const root = allFolders.find(f => f.parentId === null);

  // Evitamos incluir el nombre del Matter raíz en la ruta visual
  while (current && current.parentId !== null && current.id !== root.id) {
    path.unshift(current.name);
    current = allFolders.find(f => f.id === current.parentId);
  }
  
  return "/" + path.join("/");
}

/**
 * Función recursiva para construir una lista de items para un SelectionInput,
 * representando una estructura de árbol con indentación.
 * @param {Array<Object>} allFolders - La lista plana de todas las carpetas.
 * @param {string} parentId - El ID del padre actual para buscar hijos.
 * @param {string} prefix - El prefijo de indentación a usar para este nivel.
 * @return {Array<Object>} Una lista de objetos {text, value} para los items.
 */
function buildTreeItemsRecursive_(allFolders, parentId, prefix) {
  let items = [];
  const children = allFolders.filter(f => f.parentId === parentId);
  
  children.forEach(child => {
    items.push({
      // ***** CAMBIO AQUÍ: Añadimos el emoji *****
      text: `${prefix}📁 ${child.name}`,
      value: child.id
    });
    
    const childItems = buildTreeItemsRecursive_(allFolders, child.id, `  ${prefix.replace('└─', '│ ')}└─ `);
    items = items.concat(childItems);
  });
  
  return items;
}

/**
 * Construye la tarjeta que muestra el árbol de carpetas con radio buttons.
 */
function buildFolderTreeSelectionCard_() {
  const allFolders = JSON.parse(CacheService.getUserCache().get('folder_list') || '[]');
  
  log_('cache_state.build_card_ui', { 
    count: allFolders.length, 
    hash: getListFingerprint_(allFolders)
  });

  const rootFolder = allFolders.find(f => f.parentId === null);
  if (!rootFolder) throw new Error("Matter root folder not found in cache.");

  const treeItems = buildTreeItemsRecursive_(allFolders, rootFolder.id, '└─ ');

  const b = CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader().setTitle("Select a Destination Folder"));

  const selection = CardService.newSelectionInput()
    .setType(CardService.SelectionInputType.RADIO_BUTTON)
    .setFieldName("destination_folder_id")
    .setTitle("Folder Structure");
    
  selection.addItem(`🏠 ${rootFolder.name} (Root)`, rootFolder.id, true);
  
  treeItems.forEach(item => {
    selection.addItem(item.text, item.value, false);
  });
  
  b.addSection(CardService.newCardSection().addWidget(selection));
  
  const buttonSet = CardService.newButtonSet()
    .addButton(CardService.newTextButton()
      .setText("SELECT")
      .setTextButtonStyle(CardService.TextButtonStyle.FILLED)
      .setBackgroundColor('#3ED79F')
      .setOnClickAction(CardService.newAction().setFunctionName("onFolderTreeSelect_")))
    .addButton(CardService.newTextButton()
      .setText("Create New Folder")
      .setOnClickAction(CardService.newAction().setFunctionName("onCreateFolderInTreeClick_"))
      .setTextButtonStyle(CardService.TextButtonStyle.TEXT)
      );

  b.addSection(CardService.newCardSection().addWidget(buttonSet));
      
  return b.build();
}

/**
 * Se ejecuta cuando el usuario pulsa "SELECT" tras elegir una carpeta del árbol.
 * ¡VERSIÓN CORREGIDA! Guarda la elección y regresa a la pantalla de origen correcta.
 */
function onFolderTreeSelect_(e) {
  try {
    const selectedFolderId = e.formInput.destination_folder_id;
    if (!selectedFolderId) {
      return buildToast_("Please select a folder.");
    }
    
    const allFolders = JSON.parse(CacheService.getUserCache().get('folder_list') || '[]');
    const selectedFolder = allFolders.find(f => f.id === selectedFolderId);

    if (!selectedFolder) {
      throw new Error("Selected folder not found in cache. Please try again.");
    }
    
    // 1. Obtenemos la ruta completa y guardamos la elección en la caché
    const fullPath = getFolderPath_(selectedFolderId, allFolders);
    saveDestinationFolderToCache_({
      id: selectedFolder.id,
      name: selectedFolder.name,
      path: fullPath
    });

    // 2. ¡NUEVO! Leemos el origen para saber a qué tarjeta volver
    const cache = CacheService.getUserCache();
    const origin = cache.get('folder_origin');
    log_('onFolderTreeSelect_.returning_to_origin', { origin: origin });

    let cardToRebuild;
    let nav = CardService.newNavigation();

    // 3. Decidimos qué tarjeta reconstruir
    switch (origin) {
      case 'combined':
        // Recargamos la tarjeta principal (la que tú esperas)
        const mailMeta = readMetadataFromCache_();
        const details = readThreadDetailsFromCache_();
        let suggestions = [];
        try { suggestions = JSON.parse(userProps_().getProperty(PROPS.LAST_SUGGESTED_LIST) || "[]"); } catch (_) {}
        const linkedMessageIds = apiGetLinkedMessages_(mailMeta.threadId);
        
        // Reconstruimos el estado de la UI
        const chosenMatter = readChosenMatterFromCache_();
        const uiState = { suggestedId: chosenMatter.id || "", searchText: chosenMatter.label || "" };

        cardToRebuild = buildCombinedViewCard_(uiState, details, suggestions, linkedMessageIds);
        nav.updateCard(cardToRebuild);
        break;

      case 'detail':
        // Recargamos la tarjeta de detalles
        const messageIdHeader = cache.get('current_linking_messageIdHeader');
        cardToRebuild = buildLinkSingleEmailCard_(messageIdHeader);
        nav.updateCard(cardToRebuild);
        break;
        
      // (Mantenemos el caso de 'preview' por si lo usas en otro lado)
      case 'preview':
         const meta = readMetadataFromCache_();
         const { items } = getCurrentMessageAndAttachments_(e);
         cardToRebuild = buildPreviewCard_(items, meta);
         nav.updateCard(cardToRebuild);
         break;

      default:
        // Si no sabemos de dónde venimos, volvemos a la raíz por seguridad.
        log_('onFolderTreeSelect_.unknown_origin', { origin: origin });
        cardToRebuild = buildOpenEmailHintCard_();
        nav.popToRoot().pushCard(cardToRebuild);
        break;
    }

    // 4. Limpiamos el 'origin' de la caché
    cache.remove('folder_origin');
    
    // 5. Devolvemos la navegación
    return CardService.newActionResponseBuilder().setNavigation(nav).build();

  } catch (err) {
    log_('onFolderTreeSelect_.error', String(err));
    return buildToast_(`Error selecting folder: ${err.message}`);
  }
}

function onCreateFolderInTreeClick_(e) {
  try {
    // Leemos el ID de la carpeta que está seleccionada con el radio button
    const parentId = e.formInput.destination_folder_id;
    if (!parentId) {
      return buildToast_("Please select a parent folder first.");
    }
    
    // Mostramos la tarjeta para crear la carpeta, pasándole el ID del padre
    const card = buildCreateFolderCard_(parentId);
    const nav = CardService.newNavigation().pushCard(card);
    return CardService.newActionResponseBuilder().setNavigation(nav).build();

  } catch (err) {
    log_('onCreateFolderInTreeClick_.error', String(err));
    return buildToast_("An error occurred.");
  }
}

/**
 * Genera una "huella digital" (hash) de la lista de carpetas para depuración.
 * @param {Array<Object>} list - La lista de carpetas.
 * @return {string} Un hash corto representando el estado de la lista.
 */
function getListFingerprint_(list) {
  try {
    const listString = JSON.stringify(list || []);
    return Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, listString)
      .map(b => (b & 0xFF).toString(16).padStart(2, '0'))
      .join('')
      .slice(0, 8); // Tomamos solo los primeros 8 caracteres para que sea legible
  } catch (e) {
    return 'error-hashing';
  }
}