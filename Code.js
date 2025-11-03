/******************************************************************
 * Maatdesk Gmail Add-on – v2.8 (Versión Final Corregida)
 *
 *
 ******************************************************************/

/* ========= 0) Constantes y Configuración ========= */
const INCLUDE_BODY_HTML = true;
const INCLUDE_BODY_PLAIN = false;
const SUGGEST_MIN_LEN = 2;
const SUGGEST_CACHE_TTL_s = 60;
const SUGGEST_DEBOUNCE_ms = 300;

const PROPS = {
  ACCESS_TOKEN: "OIDC_AT",
  REFRESH_TOKEN: "OIDC_RT",
  TOKEN_EXPIRY: "OIDC_EXP",
  OIDC_STATE: "OIDC_STATE",
  OIDC_VERIFIER: "OIDC_VERIFIER",
  LAST_SUGGESTED_LIST: "MD_last_suggested_list",
  LAST_SEARCH_SUGGESTIONS: "MD_last_search_suggestions",
  FORCE_PROMPT_LOGIN: "MD_FORCE_PROMPT_LOGIN",
  USER_ID: 'MD_USER_ID',
  AUTH_COMPLETED: "MD_AUTH_COMPLETED",
};

const OIDC = {
  AUTH_BASE: PropertiesService.getScriptProperties().getProperty("AUTH_BASE"),
  AUTHORIZE_URL: PropertiesService.getScriptProperties().getProperty("AUTHORIZE_URL"),
  TOKEN_URL: PropertiesService.getScriptProperties().getProperty("TOKEN_URL"),
  END_SESSION_URL: PropertiesService.getScriptProperties().getProperty("END_SESSION_URL"),
  CLIENT_ID: "public_web_client",
  SCOPES: "openid profile email offline_access lpm_api lpm_api.all",
  REDIRECT_URI:
    "https://script.google.com/macros/s/AKfycbxfJtZJj7Cc004ytOAz7f69GJWuQgwYObAANlYAm2MMR07rZ2H20xJAsh4QglYEOf_f/exec",
};

const MD = {
  API: PropertiesService.getScriptProperties().getProperty("API_URL"),
  APP: PropertiesService.getScriptProperties().getProperty("APP_URL"),
};

const MAATDESK_LABEL_NAME = "Maatdesk Linked";

/* ========= 1) Utilidades (PKCE, Cache, Logging) ========= */
function cachePut_(k, v, ttl) {
  try {
    CacheService.getUserCache().put(k, v, ttl);
  } catch (_) {}
}
function cacheGet_(k) {
  try {
    return CacheService.getUserCache().get(k) || "";
  } catch (_) {
    return "";
  }
}
function b64url_(bytes) {
  return Utilities.base64EncodeWebSafe(bytes).replace(/=+$/, "");
}
function randomStr_(len) {
  const c =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~";
  let s = "";
  for (let i = 0; i < len; i++)
    s += c.charAt(Math.floor(Math.random() * c.length));
  return s;
}
function sha256Bytes_(str) {
  return Utilities.computeDigest(
    Utilities.DigestAlgorithm.SHA_256,
    str,
    Utilities.Charset.UTF_8,
  );
}
function codeChallenge_(v) {
  return b64url_(sha256Bytes_(v));
}
/**
 * Escribe un mensaje en el log, incluyendo siempre el client_id.
 * @param {string} tag - Una etiqueta para identificar el log.
 * @param {Object} obj - Un objeto para convertir a JSON y registrar.
 */
function log_(tag, obj) {
  try {
    const userEmail = Session.getActiveUser().getEmail();
    const scrub = (v) =>
      typeof v === "string" && v.length > 16
        ? v.slice(0, 6) + "…" + v.slice(-4)
        : v;
    const safe = JSON.stringify(obj, (k, v) =>
      /^(access_token|refresh_token|id_token|authorization)$/i.test(k)
        ? scrub(v)
        : v,
    );

    console.log(`[MD][${userEmail}][${tag}] ${safe}`);
  } catch (e) {
    console.log(`[MD][${userEmail}][${tag}]`, obj);
  }
}

/* ========= 2) Gestión de Tokens y Sesión ========= */
function userProps_() {
  return PropertiesService.getUserProperties();
}
function saveTokens_({ access_token, refresh_token, expires_in, id_token = '' }) {
  const exp = Date.now() + Math.max(30, expires_in || 1800) * 1000;
  let userId = '';
  if (id_token) {
    const tokenPayload = parseJwt_(id_token);
    userId = tokenPayload.sub || '';
    log_('auth.user_id_found', { userId: userId, from: 'id_token' });
  }
  // TODO: Asegúrate de que apiGetUserIdFromSession_() exista o elimínala si no la necesitas.
  if (!userId) {
     log_('auth.no_userid_in_token', { msg: "Falling back to session API to get UserModel." });
     Utilities.sleep(500);
     // userId = apiGetUserIdFromSession_(); // Asegúrate que esta función exista
     if (!userId) log_('auth.user_id_fallback_failed', {}); // Log si el fallback también falla
  }

  // Guardamos solo los tokens principales en PropertiesService
  userProps_().setProperties(
    {
      [PROPS.ACCESS_TOKEN]: access_token || "",
      [PROPS.REFRESH_TOKEN]: refresh_token || "",
      [PROPS.TOKEN_EXPIRY]: String(exp),
      // Solo guardamos USER_ID si lo obtuvimos
      ...(userId && { [PROPS.USER_ID]: userId })
    },
    true,
  );
  log_("tokens.saved", { hasAT: !!access_token, hasRT: !!refresh_token, finalUserId: userId, exp });
}

function clearTokens_() {
  [
    PROPS.ACCESS_TOKEN,
    PROPS.REFRESH_TOKEN,
    PROPS.TOKEN_EXPIRY,
    PROPS.OIDC_STATE,
    PROPS.OIDC_VERIFIER,
  ].forEach((k) => userProps_().deleteProperty(k));
}
function refreshToken_() {
  const rt = userProps_().getProperty(PROPS.REFRESH_TOKEN);
  if (!rt) {
    log_("refresh.noRT", {});
    return null;
  }
  const body = {
    grant_type: "refresh_token",
    client_id: OIDC.CLIENT_ID,
    refresh_token: rt,
  };
  const resp = UrlFetchApp.fetch(OIDC.TOKEN_URL, {
    method: "post",
    contentType: "application/x-www-form-urlencoded",
    muteHttpExceptions: true,
    payload: Object.keys(body)
      .map((k) => `${encodeURIComponent(k)}=${encodeURIComponent(body[k])}`)
      .join("&"),
  });
  if (resp.getResponseCode() >= 200 && resp.getResponseCode() < 300) {
    const t = JSON.parse(resp.getContentText() || "{}");
    saveTokens_(t);
    return t.access_token || null;
  }
  log_("refresh.fail", {
    status: resp.getResponseCode(),
    body: resp.getContentText() || "",
  });
  clearTokens_();
  return null;
}

function getAccessTokenLax_() {
  log_("getAccessTokenLax_.starting", {}); // <-- Log A: Entramos a la función
  const props = userProps_();
  const at = props.getProperty(PROPS.ACCESS_TOKEN);
  const rt = props.getProperty(PROPS.REFRESH_TOKEN);
  const exp = parseInt(props.getProperty(PROPS.TOKEN_EXPIRY) || "0", 10);
  const now = Date.now();
  const isExpired = now >= (exp || 0);

  // Log detallado de lo que se leyó
  log_("getAccessTokenLax_.read_from_props", {
    hasAT: !!at,
    hasRT: !!rt,
    exp: exp,
    now: now,
    isExpired: isExpired
  }); // <-- Log B: ¿Qué encontramos en Properties?

  if (at && !isExpired) {
    log_("getAccessTokenLax_.returning_valid_at", {}); // <-- Log C: Devolvemos AT válido
    return at;
  }

  // Si llegamos aquí, o no hay AT o está expirado. Intentamos refrescar.
  log_("getAccessTokenLax_.needs_refresh", { hasRT: !!rt }); // <-- Log D: ¿Tenemos RT para intentar refrescar?
  const refreshedToken = refreshToken_(); // refreshToken_ ya tiene sus propios logs
  log_("getAccessTokenLax_.refresh_result", { hasRefreshedToken: !!refreshedToken }); // <-- Log E: ¿Funcionó el refresco?
  return refreshedToken; // Devolvemos el token refrescado (o null si falló)
}

function hasUsableSession_() {
  log_("hasUsableSession_.checking", {}); // <-- Log 1: Empezamos a comprobar
  try {
    const token = getAccessTokenLax_(); // Llama a la función que intenta obtener/refrescar
    const hasToken = !!token;
    log_("hasUsableSession_.result", { hasToken: hasToken }); // <-- Log 2: Resultado de getAccessTokenLax_
    return hasToken;
  } catch (err) {
    // Si getAccessTokenLax_ lanza error (ej. SESSION_EXPIRED), devolvemos false
    log_("hasUsableSession_.check_failed", { error: String(err) }); // <-- Log 3: Error
    return false;
  }
}

/* ========= 3) Flujo de Autenticación (Login y Logout) ========= */
function onConnectClick_() {
  const redirectUri = OIDC.REDIRECT_URI;
  const state = randomStr_(32);
  const verifier = randomStr_(64);
  const challenge = codeChallenge_(verifier);
  userProps_().setProperties({
    [PROPS.OIDC_STATE]: state,
    [PROPS.OIDC_VERIFIER]: verifier,
  });
  const q = {
    response_type: "code",
    client_id: OIDC.CLIENT_ID,
    redirect_uri: redirectUri,
    scope: OIDC.SCOPES,
    code_challenge: challenge,
    code_challenge_method: "S256",
    state,
  };
  if (consumeForcePromptLogin_()) {
    q.prompt = "login";
  }
  const authUrl =
    OIDC.AUTHORIZE_URL +
    "?" +
    Object.keys(q)
      .map((k) => `${encodeURIComponent(k)}=${encodeURIComponent(q[k])}`)
      .join("&");
  const open = CardService.newOpenLink()
    .setUrl(authUrl)
    .setOpenAs(CardService.OpenAs.OVERLAY)
    .setOnClose(CardService.OnClose.RELOAD_ADD_ON);
  return CardService.newActionResponseBuilder().setOpenLink(open).build();
}
function onLogoutClick_() {
  wipeLocalState_();
  setForcePromptLogin_();
  const logoutUrl = OIDC.END_SESSION_URL;
  const open = CardService.newOpenLink()
    .setUrl(logoutUrl)
    .setOpenAs(CardService.OpenAs.OVERLAY)
    .setOnClose(CardService.OnClose.RELOAD_ADD_ON);
  const nav = CardService.newNavigation().updateCard(
    buildConnectCard_("You have been signed out."),
  );
  return CardService.newActionResponseBuilder()
    .setOpenLink(open)
    .setNavigation(nav)
    .build();
}

function doGet(req) {
  try {
    if (req?.parameter?.code) {
      // 1. Intercambiamos el código por tokens (llama a saveTokens_)
      exchangeCodeForTokens_(req.parameter.code, req.parameter.state);

      // --- PAUSA Y VERIFICACIÓN ---
      try {
          log_("doGet.pausing_before_read_back", {});
          // 2. Añadimos una pausa de 1 segundo para dar tiempo a PropertiesService
          Utilities.sleep(1000);
          // 3. Intentamos leer de vuelta uno de los tokens guardados para loguear
          const checkRT = userProps_().getProperty(PROPS.REFRESH_TOKEN);
          log_("doGet.read_back_check_after_pause", { hasRT: !!checkRT });
      } catch (delayErr) {
          log_("doGet.delay_or_read_error", String(delayErr));
      }
      // --- FIN PAUSA Y VERIFICACIÓN ---
    }
    // 4. Mostramos la página de éxito y cerramos la ventana
    const html = `<!doctype html><html><head><meta charset="utf-8"><title>Success</title><style>body{font-family:system-ui,sans-serif;text-align:center;padding-top:40px;color:#333}h2{color:#0a0}</style></head><body><h2>✅ Success!</h2><p>You can close this window.</p><script>setTimeout(function(){google.script.host.close()},500);</script></body></html>`;
    return HtmlService.createHtmlOutput(html).setXFrameOptionsMode(
      HtmlService.XFrameOptionsMode.ALLOWALL,
    );
  } catch (err) {
    log_("doGet.error", String(err));
    return HtmlService.createHtmlOutput(
      `<h2>❌ Error</h2><pre>${String(err)}</pre>`,
    ).setXFrameOptionsMode(HtmlService.XFrameOptionsMode.ALLOWALL);
  }
}

function exchangeCodeForTokens_(code, state) {
  const savedState = userProps_().getProperty(PROPS.OIDC_STATE);
  const verifier = userProps_().getProperty(PROPS.OIDC_VERIFIER);
  if (!code || !verifier || (savedState && state && savedState !== state))
    throw new Error("OIDC parameter mismatch");
  const body = {
    grant_type: "authorization_code",
    client_id: OIDC.CLIENT_ID,
    code,
    redirect_uri: OIDC.REDIRECT_URI,
    code_verifier: verifier,
  };
  const resp = UrlFetchApp.fetch(OIDC.TOKEN_URL, {
    method: "post",
    contentType: "application/x-www-form-urlencoded",
    payload: Object.keys(body)
      .map((k) => `${encodeURIComponent(k)}=${encodeURIComponent(body[k])}`)
      .join("&"),
    muteHttpExceptions: true,
  });
  if (resp.getResponseCode() >= 300)
    throw new Error(
      `Token endpoint error ${resp.getResponseCode()}: ${resp.getContentText()}`,
    );
  saveTokens_(JSON.parse(resp.getContentText() || "{}"));
  userProps_().deleteProperty(PROPS.OIDC_STATE);
  userProps_().deleteProperty(PROPS.OIDC_VERIFIER);
}

/* ========= 4) Puntos de Entrada Principales del Add-on ========= */
function onHomepage() {
  try {
    // Si hay sesión, muestra la pantalla de inicio normal
    if (hasUsableSession_()) {
      /* ensurePinFromSession_(); */
      return buildOpenEmailHintCard_();
    }
    // Si NO hay sesión, SIEMPRE muestra la pantalla de conexión
    return buildConnectCard_("Sign in to Maatdesk to continue.");

  } catch (err) {
    // Manejo de error SESSION_EXPIRED (sin cambios)
    if (String(err.message).includes("SESSION_EXPIRED")) {
      log_("session.expired", { context: "onHomepage" });
      wipeLocalState_();
      setForcePromptLogin_();
      return buildConnectCard_(
        "Your session has expired. Please sign in again.",
      );
    } else {
      log_("onHomepage.FATAL", String(err));
      return errorCard_("An unexpected error occurred.");
    }
  }
}

/**
 * Aplica una etiqueta de Gmail a un hilo específico.
 * @param {string} threadId - El ID del hilo de Gmail.
 * @param {string} labelName - El nombre de la etiqueta a aplicar.
 */
function applyGmailLabel_(threadId, labelName) {
  try {
    // 1. Obtenemos el objeto de la etiqueta por su nombre
    let label = GmailApp.getUserLabelByName(labelName);
    log_('gmail.label.list', { label });
    
    // 2. Si no existe (esto no debería pasar si la leímos del dropdown, pero por si acaso)
    if (!label) {
      label = GmailApp.createLabel(labelName);
      log_('gmail.label.created', { label: labelName });
    }
    
    // 3. Obtenemos el hilo y aplicamos la etiqueta
    const thread = GmailApp.getThreadById(threadId);
    if (thread) {
      thread.addLabel(label);
      log_('gmail.label.applied', { threadId: threadId, label: labelName });
    }
  } catch (e) {
    log_('gmail.label.fatal', { error: String(e), labelName: labelName });
  }
}

/**
 * PUNTO DE ENTRADA AL ABRIR UN MENSAJE
 * ¡VERSIÓN COMPLETA CON LOGS DETALLADOS DE IDS INICIALES!
 */
function onGmailMessageOpen(e) {
  log_("onGmailMessageOpen.START", { eventObject: e }); // Log del evento completo
  try {
    // --- 1. Chequeo de Sesión ---
    let initialTokenCheck = null;
    try {
        initialTokenCheck = getAccessTokenLax_(); // Intenta obtener/refrescar token
    } catch(sessionErr) {
        // Si getAccessTokenLax_ lanza SESSION_EXPIRED, lo relanzamos para el catch principal
        if (String(sessionErr.message).includes("SESSION_EXPIRED")) {
             log_("onGmailMessageOpen.SESSION_EXPIRED_during_initial_check", {});
             throw sessionErr;
        }
        // Otro error al obtener token, lo logueamos pero continuamos (trataremos como sin sesión)
        log_("onGmailMessageOpen.initialTokenError", String(sessionErr));
    }

    // Si no hay token válido (ni siquiera uno refrescado), mostramos la pantalla de conexión
    if (!initialTokenCheck) {
        log_("onGmailMessageOpen.NO_SESSION_showing_connect_card", {});
        // Verificamos si la autenticación se completó para evitar bucles (aunque eliminamos buildFinalizingCard_)
        if (userProps_().getProperty(PROPS.AUTH_COMPLETED) === "true") {
           // Si AUTH_COMPLETED está true pero no hay token, algo raro pasó. Limpiamos y pedimos login.
           log_("onGmailMessageOpen.AUTH_COMPLETED_but_no_token", {});
           wipeLocalState_();
           setForcePromptLogin_();
           return buildConnectCard_("Connection issue. Please sign in again.");
        }
        return buildConnectCard_("Sign in to Maatdesk to continue.");
    }
    // Si llegamos aquí, la sesión es válida (o se pudo refrescar).
    log_("onGmailMessageOpen.SESSION_OK", {});
    // Ya no necesitamos ensurePinFromSession_ aquí

    // --- 2. OBTENER METADATOS Y LOGUEAR IDS ---
    const evtMsgId = // Obtenemos el ID del evento (debería ser msg-f:...)
      (e && e.gmail && e.gmail.messageId) ||
      (e && e.messageMetadata && e.messageMetadata.messageId);
    log_("onGmailMessageOpen.EVENT_MSG_ID", { evtMsgId: evtMsgId }); // Log ID del evento

    if (!evtMsgId) {
        log_("onGmailMessageOpen.ERROR_NO_EVENT_ID", {});
        throw new Error("Could not get message identifier from event.");
    }

    // Aseguramos que GmailApp tenga el token correcto para este mensaje
    ensureGmailToken_(e);

    let msgObjectFromEvent = null;
    let msgHexId = null; // ID Hexadecimal (ej: 1987...)
    let msgRfcId = null; // ID RFC 822 (ej: msg-f:...)
    let msgThreadId = null; // ID Hexadecimal del hilo

    try {
        // Obtenemos el objeto Message usando el ID del evento
        msgObjectFromEvent = GmailApp.getMessageById(evtMsgId);
        if(msgObjectFromEvent) {
            // Obtenemos ambos IDs directamente del objeto Message
            msgHexId = msgObjectFromEvent.getId(); // ESTE es el que devuelve formato Hex en este contexto
            msgRfcId = evtMsgId; // Mantenemos el ID del evento como el RFC ID fiable
            msgThreadId = msgObjectFromEvent.getThread().getId(); // Obtenemos el ID del hilo
        } else {
            // Si no se pudo obtener el objeto mensaje (muy raro)
            log_("onGmailMessageOpen.ERROR_MSG_OBJECT_NULL", { eventId: evtMsgId });
            throw new Error(`GmailApp.getMessageById returned null for event ID: ${evtMsgId}`);
        }
    } catch (getMsgErr) {
        log_("onGmailMessageOpen.ERROR_GETTING_MESSAGE_OBJECT", { eventId: evtMsgId, error: String(getMsgErr) });
        // Si falla aquí, no podemos continuar
        throw getMsgErr;
    }

    // Log exhaustivo de los IDs obtenidos/derivados
    log_("onGmailMessageOpen.OBTAINED_AND_DERIVED_IDS", {
        eventId: evtMsgId,          // El ID original del evento (esperamos msg-f:...)
        idFromGetId: msgHexId,      // El ID devuelto por msg.getId() (esperamos hex)
        threadIdFromGetThread: msgThreadId, // El ID del hilo (hex)
        finalRfcIdUsed: msgRfcId    // El ID que usaremos como identificador único msg-f:...
     });

    // Creamos el objeto mailMeta para guardar en caché
    const mailMeta = {
      subject: msgObjectFromEvent.getSubject(),
      from: msgObjectFromEvent.getFrom(),
      to: msgObjectFromEvent.getTo() || "",
      sentAtIso: msgObjectFromEvent.getDate().toISOString(),
      threadId: msgThreadId, // Guardamos el ID del hilo (hex)
      messageId: msgRfcId,  // Guardamos el ID del mensaje (msg-f:...)
    };
    log_("onGmailMessageOpen.MAILMETA_TO_CACHE", mailMeta); // Log antes de guardar en caché
    saveMetadataToCache_(mailMeta); // Guardamos en caché

    // --- 3. Obtener IDs Vinculados ---
    // Llamamos a la API para obtener la lista de messageIds (msg-f:...) vinculados a este hilo
    let linkedMessageIds = []; // Inicializa por defecto
    try {
        linkedMessageIds = apiGetLinkedMessages_(mailMeta.threadId); // Puede lanzar error (SESSION_EXPIRED o API Error)
        log_("onGmailMessageOpen.LINKED_DATA_FROM_API_SUCCESS", { linkedData: linkedMessageIds });
    } catch (apiErr) {
        log_("onGmailMessageOpen.apiGetLinkedMessages_FAILED_in_caller", { error: String(apiErr) });
        // Si el error es de sesión, lo re-lanzamos para el catch principal que muestra el login
        if (String(apiErr.message).includes("SESSION_EXPIRED")) {
            throw apiErr;
        }
        // ¡¡AQUÍ MOSTRAMOS UNA TARJETA DE ERROR ESPECÍFICA!!
        // Para cualquier otro error de API (ej. 404), mostramos una tarjeta indicando el fallo.
        log_("onGmailMessageOpen.SHOWING_API_ERROR_CARD", {});
        // Puedes crear una función helper o construir la tarjeta aquí mismo:
        return CardService.newCardBuilder()
                .setHeader(CardService.newCardHeader().setTitle("Error"))
                .addSection(CardService.newCardSection()
                    .addWidget(CardService.newTextParagraph()
                    .setText("Could not retrieve link status from the server. Please try again later or contact support if the problem persists.")) // Mensaje claro
                )
                .build();
        // La ejecución se detiene aquí si hubo un error de API.
    }
    // --- 4. Obtener Detalles del Hilo ---
    const details = getThreadDetails_(mailMeta.threadId); // Pasamos el threadId (hex)
    log_("onGmailMessageOpen.THREAD_DETAILS_FROM_GETDETAILS", { detailsCount: details.length, firstDetail: details[0] }); // Log de lo que devuelve getThreadDetails_
    saveThreadDetailsToCache_(details); // Guardamos los detalles en caché

    // --- 5. Obtener Sugerencias de Matters ---
    const myEmail = Session.getActiveUser().getEmail() || "";
    // Determinamos qué dirección usar para buscar sugerencias
    const useAddress =
      (mailMeta.from || "").toLowerCase().includes((myEmail || "").toLowerCase())
        ? mailMeta.to || ""
        : mailMeta.from || "";
    let suggestions = [];
    try {
      // Llamamos a la API para obtener sugerencias basadas en la dirección
      suggestions = apiByFromTo_(useAddress); // Puede lanzar SESSION_EXPIRED
    } catch (err) {
      // Si el error NO es de sesión, lo logueamos pero continuamos sin sugerencias
      if (!String(err.message).includes("SESSION_EXPIRED")) {
         log_("onGmailMessageOpen.SUGGESTIONS_ERROR", { address: useAddress, error: String(err)});
      } else {
         // Si es error de sesión, lo relanzamos para el catch principal
         log_("onGmailMessageOpen.SESSION_EXPIRED_during_suggestions", {});
         throw err;
      }
    }
    // Guardamos las sugerencias para usarlas después (ej. en onCombinedStateChange_)
    try {
      userProps_().setProperty(
        PROPS.LAST_SUGGESTED_LIST,
        JSON.stringify(suggestions || []), // Guarda como JSON string
      );
    } catch (propErr) { log_("onGmailMessageOpen.ERROR_SAVING_SUGGESTIONS", {error: String(propErr)}); }

    // --- 6. Construir Tarjeta Principal ---
    const uiState = { suggestedId: "", searchText: "" }; // Estado inicial de la UI
    log_("onGmailMessageOpen.BUILDING_CARD", {
        uiState: uiState,
        threadDetailsCount: details.length,
        suggestionsCount: suggestions.length,
        linkedIdsCount: (linkedMessageIds || []).length
     });
    // Llamamos al constructor de la tarjeta principal, pasando todos los datos
    return buildCombinedViewCard_(uiState, details, suggestions, linkedMessageIds);

  // --- Catch Principal ---
  } catch (err) {
    // Manejo centralizado de errores
    log_("onGmailMessageOpen.MAIN_CATCH", { error: String(err), stack: err.stack }); // Logueamos el error completo
    // Si es error de sesión, limpiamos todo y mostramos login
    if (String(err.message).includes("SESSION_EXPIRED")) {
      log_("session.expired", { context: "onGmailMessageOpen_MainCatch" });
      wipeLocalState_();      // Limpia tokens y caché
      setForcePromptLogin_(); // Fuerza login en la próxima interacción OIDC
      return buildConnectCard_( // Muestra la tarjeta de login
        "Your session has expired. Please sign in again.",
      );
    } else {
      // --- AQUÍ ES DONDE VA EL TOAST ---
      // Para CUALQUIER OTRO error (incluyendo un posible error 404 de la API
      // si modificamos apiGetLinkedMessages_ para que lo lance),
      // mostramos un Toast genérico y luego la tarjeta de error.
      log_("onGmailMessageOpen.FATAL", String(err));

      // ¡Añade esta línea!
      CardService.newActionResponseBuilder()
        .setNotification(CardService.newNotification()
        .setText("Error communicating with the server. Please try again later.")) // <-- El mensaje en inglés
        .build(); // Construimos la notificación para que se muestre

      // Después del Toast (o en lugar de la tarjeta de error si prefieres),
      // decidimos qué tarjeta mostrar. La de error es segura.
      return errorCard_("Could not load email data. Please try again or contact support.");
    }
  }
}

/* ========= 5) Handlers de UI y Acciones ========= */
function onCheckSession_(e) {
  log_("onCheckSession_.starting", {}); //
  try {
    // 1. Comprueba si hay sesión válida
    if (!hasUsableSession_()) { //
      log_("onCheckSession_.no_session", {}); //
      const card = buildConnectCard_("Please sign in to continue."); //
      // Usamos updateCard aquí porque solo mostramos el login
      const nav = CardService.newNavigation().updateCard(card); //
      return CardService.newActionResponseBuilder().setNavigation(nav).build(); //
    }

    // 2. ¡SI HAY SESIÓN! Forzamos la recarga completa
    log_("onCheckSession_.session_ok_forcing_full_reload", {}); //
    try {
      // Llamamos a onGmailMessageOpen para que genere la tarjeta principal
      // con los datos MÁS RECIENTES (incluyendo la nueva lista de vinculados)
      const mainCard = onGmailMessageOpen(e); //

      // ¡¡CAMBIO CLAVE!! Limpiamos la pila y empujamos la nueva tarjeta
      const nav = CardService.newNavigation()
          .popToRoot() // Vuelve a la base
          .pushCard(mainCard); // Añade la tarjeta principal recién generada

      return CardService.newActionResponseBuilder().setNavigation(nav).build(); //
    } catch (openEmailErr) {
      // Si onGmailMessageOpen falla (ej. no hay correo abierto),
      // mostramos la pantalla genérica de inicio (popToRoot + pushCard también)
      log_("onCheckSession_.onGmailMessageOpen_failed_showing_homepage", { error: String(openEmailErr) }); //
      const homeCard = onHomepage(); //
      const nav = CardService.newNavigation()
          .popToRoot()
          .pushCard(homeCard);
      return CardService.newActionResponseBuilder().setNavigation(nav).build(); //
    }

  } catch (err) {
    // Error general en onCheckSession_
    log_("onCheckSession_.error", String(err)); //
    // Si el error es de sesión, limpiamos y mostramos login (updateCard está bien aquí)
    if (String(err.message).includes("SESSION_EXPIRED")) { //
        wipeLocalState_(); //
        setForcePromptLogin_(); //
        const card = buildConnectCard_("Your session has expired. Please sign in again."); //
        const nav = CardService.newNavigation().updateCard(card); //
        return CardService.newActionResponseBuilder().setNavigation(nav).build(); //
    }
    // Otro error, mostramos un mensaje genérico
    return buildToast_("Could not refresh view: " + String(err)); //
  }
}

/**
 * Se ejecuta para obtener sugerencias de Matters.
 * ¡VERSIÓN CORREGIDA! Ahora funciona en ambas pantallas.
 */
function onMatterSearchSuggest_(e) {
  try {
    if (!hasUsableSession_()) {
      log_("onMatterSearchSuggest_.no_session", {});
      return CardService.newSuggestionsResponseBuilder()
        .setSuggestions(CardService.newSuggestions())
        .build();
    }
    
    const inputs = e?.commonEventObject?.formInputs || {};
    const q = (
        inputs.search_q?.stringInputs?.value?.[0] || // El de la pantalla principal
        inputs.detail_search_q?.stringInputs?.value?.[0] || // El de la pantalla de detalles
        ""
    ).trim();

    log_("onMatterSearchSuggest_.query", q);
    if (q.length < SUGGEST_MIN_LEN) {
      return CardService.newSuggestionsResponseBuilder()
        .setSuggestions(CardService.newSuggestions())
        .build();
    }
    const gateKey = "SUGG_GATE:" + q.toLowerCase();
    if (cacheGet_(gateKey)) {
      const cached = cacheGet_("SUGG:" + q.toLowerCase());
      const sug = CardService.newSuggestions();
      if (cached) JSON.parse(cached).forEach((x) => sug.addSuggestion(x.label));
      return CardService.newSuggestionsResponseBuilder()
        .setSuggestions(sug)
        .build();
    }
    cachePut_(gateKey, "1", Math.ceil(SUGGEST_DEBOUNCE_ms / 1000));
    const ck = "SUGG:" + q.toLowerCase();
    log_("onMatterSearchSuggest_.cache", ck);
    const hit = cacheGet_(ck);
    if (hit) {
      const sug = CardService.newSuggestions();
      JSON.parse(hit).forEach((x) => sug.addSuggestion(x.label));
      return CardService.newSuggestionsResponseBuilder()
        .setSuggestions(sug)
        .build();
    }
    log_("onMatterSearchSuggest_.hit", hit);
    const items = apiByLabel_(q, 8);
    log_("onMatterSearchSuggest_.items", items);
    cachePut_(ck, JSON.stringify(items || []), SUGGEST_CACHE_TTL_s);
    try {
      userProps_().setProperty(
        PROPS.LAST_SEARCH_SUGGESTIONS,
        JSON.stringify(items || []),
      );
    } catch (_) {}
    const sug = CardService.newSuggestions();
    (items || []).forEach((x) => sug.addSuggestion(x.label));
    return CardService.newSuggestionsResponseBuilder()
      .setSuggestions(sug)
      .build();
  } catch (err) {
    log_("onMatterSearchSuggest_.error", String(err));
    return CardService.newSuggestionsResponseBuilder()
      .setSuggestions(CardService.newSuggestions())
      .build();
  }
}

/**
 * ¡TARJETA PRINCIPAL (VERSIÓN CORREGIDA v15)!
 * - Muestra "From" (Header) y "Linked to MD" (Widget 1) siempre visibles.
 * - Mueve "Subject" y los botones/adjuntos al área colapsable.
 */
function buildCombinedViewCard_(uiState, threadDetails, suggestions, linkedMessagesData) {
  log_("buildCombinedViewCard_.START", {
      uiState: uiState,
      threadDetailsCount: threadDetails.length,
      suggestionsCount: (suggestions || []).length, 
      linkedIdsData: linkedMessagesData 
  });
  
  const b = CardService.newCardBuilder().setHeader(
    CardService.newCardHeader()
      .setTitle("Link Thread to Maatdesk")
      .setSubtitle(`Thread with ${threadDetails.length} message(s)`)
  );
  
  const linkedInfoMap = new Map();
  if (Array.isArray(linkedMessagesData)) {
      linkedMessagesData.forEach(item => { 
          if (item.gmailId) {
              linkedInfoMap.set(item.gmailId, item.matterId); 
          }
      });
  }
  log_("buildCombinedViewCard_.LINKED_INFO_MAP_created", { mapSize: linkedInfoMap.size });

  // --- 1. Lógica de Estado ---
  let allMessagesLinked = false;
  if (threadDetails.length > 0) {
      allMessagesLinked = threadDetails.every(msg => linkedInfoMap.has(msg.messageId));
  }
  log_("buildCombinedViewCard_.link_check_all", { 
      allLinked: allMessagesLinked, 
      threadCount: threadDetails.length, 
      linkedCount: linkedInfoMap.size 
  });

  const isMatterSelected = !!uiState.suggestedId ||
    (!!uiState.searchText && uiState.searchText.trim().length > 0);
  
  const isSingleAlreadyLinked = threadDetails.length === 1 && allMessagesLinked;
  
  let linkedMatterIdForSingle = null; 
  if (isSingleAlreadyLinked) {
      const firstMsgId = threadDetails[0]?.messageId;
      linkedMatterIdForSingle = linkedInfoMap.get(firstMsgId);
  }

  // --- 2. Sección de Selección de Matter (CONDICIONAL) ---
  if (!allMessagesLinked) {
      try {
          const matterSection = CardService.newCardSection().setHeader("Select a Matter");
          if (suggestions && suggestions.length > 0) {
            const dd = CardService.newSelectionInput()
              .setType(CardService.SelectionInputType.DROPDOWN)
              .setFieldName("suggested_matter")
              .setOnChangeAction(
                CardService.newAction().setFunctionName("onSuggestionDropdownChange_"),
              )
              .addItem("— Select from suggestions —", "", !uiState.suggestedId);
            suggestions
              .slice(0, 25) 
              .forEach((it) =>
                dd.addItem(
                  it.label, 
                  String(it.id), 
                  String(it.id) === String(uiState.suggestedId),
                ),
              );
            matterSection.addWidget(dd);
          }
          const ti = CardService.newTextInput()
            .setFieldName("search_q")
            .setTitle("Or search Matter (number/title)")
            .setHint("Type to see suggestions…")
            .setValue(uiState.searchText) 
            .setSuggestionsAction( 
              CardService.newAction().setFunctionName("onMatterSearchSuggest_"),
            )
            .setOnChangeAction( 
              CardService.newAction().setFunctionName("onSearchTextChange_"),
            );
          matterSection.addWidget(ti);
          b.addSection(matterSection);
      } catch (err) { log_("buildCombinedViewCard_.ERROR_matter_section", { error: String(err) }); throw err;}
  } else {
      if (isSingleAlreadyLinked && linkedMatterIdForSingle) {
           b.addSection(
               CardService.newCardSection()
               .addWidget(
                   CardService.newTextButton()
                       .setText("View in Maatdesk")
                       .setOpenLink(CardService.newOpenLink().setUrl(`${MD.APP}/matters/${encodeURIComponent(linkedMatterIdForSingle)}/details/`))
                       .setTextButtonStyle(CardService.TextButtonStyle.FILLED)
                )
           );
      }
  }

  // --- 3. Lógica de Conteo de Adjuntos ---
  let totalSizeInBytes = 0;
  let totalAttachmentCount = 0;
  threadDetails.forEach(msg => {
    if (msg.attachments && msg.attachments.length > 0) { 
      totalAttachmentCount += msg.attachments.length;
      msg.attachments.forEach(att => {
        totalSizeInBytes += att.size;
      });
    }
  });
  const hasAttachments = totalAttachmentCount > 0;
  const totalSizeInMB = Math.ceil(totalSizeInBytes / 1024 / 1024);
  const isOverLimit = totalSizeInBytes > (50 * 1024 * 1024);
  const hasDocPermission = apiCheckDocumentPermission_();

  // --- 4. Sección de Acciones (CONDICIONAL) ---
  if (threadDetails.length > 1 && !allMessagesLinked) {
      try {
        const actionsSection = CardService.newCardSection().setHeader("Manage Thread");
        const mainButtonSet = CardService.newButtonSet(); 
        
        mainButtonSet.addButton(
            CardService.newTextButton()
              .setText("Link Emails & Save Attachments") 
              .setOnClickAction(
                CardService.newAction().setFunctionName("onDoLinkAllAndUpload_")
              )
              .setTextButtonStyle(CardService.TextButtonStyle.FILLED) 
              .setDisabled(!isMatterSelected)
        );
        
        actionsSection.addWidget(mainButtonSet);

          if (hasAttachments) {
             if (isMatterSelected && !hasDocPermission) {
               actionsSection.addWidget(
                 CardService.newTextParagraph().setText(
                   "You don’t have permission to upload documents for this matter. Please contact your administrator."
                 )
               );
             } else if (isMatterSelected && isOverLimit) {
                let sizeWarning = `The total size (~${totalSizeInMB} MB) of all attachments is too large to save together.`;
                if (isOverLimit) { 
                   actionsSection.addWidget(
                     CardService.newTextParagraph().setText(sizeWarning)
                   );
                }
             }
          }
          b.addSection(actionsSection);
      } catch (err) { log_("buildCombinedViewCard_.ERROR_actions_section", { error: String(err) }); throw err;}
  }

  // --- 5. Sección de Etiquetado (CONDICIONAL) ---
  if (isMatterSelected && !allMessagesLinked) {
      try {
          const labelDropdown = CardService.newSelectionInput()
            .setType(CardService.SelectionInputType.DROPDOWN)
            .setFieldName("selected_label");
          labelDropdown.addItem("— Do not apply label —", "", true);
          try {
            const labels = GmailApp.getUserLabels();
            labels.forEach(label => {
              labelDropdown.addItem(label.getName(), label.getName(), false);
            });
          } catch (e) { log_('buildCard.getLabels.error', String(e)); } 
          
          const optionsSection = CardService.newCardSection()
            .setHeader("Labeling Options")
            .addWidget(labelDropdown);
          b.addSection(optionsSection);
      } catch (err) { log_("buildCombinedViewCard_.ERROR_label_section", { error: String(err) }); throw err;}
  }

  // --- 6. Sección de Carpeta (CONDICIONAL) ---
  if (isMatterSelected && hasAttachments && hasDocPermission && !allMessagesLinked) {
      try {
          const destinationFolder = readDestinationFolderFromCache_();
          let folderDisplayName = `🏠 ${destinationFolder.name}`;
          
          if (destinationFolder.path && destinationFolder.path !== "/") {
            let fullPathWithIcon = `🏠${destinationFolder.path}`;
            const MAX_PATH_LENGTH = 35;
            if (fullPathWithIcon.length > MAX_PATH_LENGTH) {
              folderDisplayName = `🏠.../${destinationFolder.name}`;
            } else {
              folderDisplayName = fullPathWithIcon;
            }
          }
          
          b.addSection(
            CardService.newCardSection()
              .setHeader("Destination Folder")
              .addWidget(
                CardService.newKeyValue()
                  .setContent(folderDisplayName)
                  .setButton( 
                     CardService.newTextButton()
                      .setText("CHANGE")
                      .setOnClickAction(
                        CardService.newAction()
                          .setFunctionName("onSelectFolderClick_")
                          .setParameters({ origin: 'combined' }) 
                      )
                      .setTextButtonStyle(CardService.TextButtonStyle.TEXT) 
                      .setDisabled(!isMatterSelected)
                  )
              ),
          );
      } catch (err) { log_("buildCombinedViewCard_.ERROR_folder_section", { error: String(err) });
        throw err;}
  }

  // --- 7. Sección de Lista de Mensajes (CON LÓGICA DE ORDEN CORREGIDA v15) ---
  log_("buildCombinedViewCard_.STARTING_MESSAGE_LOOP", {});
  
  threadDetails.forEach((msg, index) => { 
    try {
        const date = new Date(msg.date).toLocaleString();
        const from = (msg.from || "").replace(/<.*?>/g, "").trim();
        
        // --- ¡LÓGICA MODIFICADA! ---
        // 1. "From" y Fecha son el encabezado (siempre visible)
        const fromText = `<b>From:</b> ${from} | ${date}`;
        const msgSection = CardService.newCardSection().setHeader(fromText);

        // 2. "Subject" (Asunto) es un widget normal
        const subjectText = `<b>Subject:</b> ${msg.subject || "(No Subject)"}`;
        
        // 3. Comprobamos el estado del vínculo
        const linkedMatterId = linkedInfoMap.get(msg.messageId);
        const isLinked = !!linkedMatterId; 
        
        if (isLinked) {
            // --- ESTADO VINCULADO ---
            
            // 4a. Hacemos que el primer widget (el estado) sea visible
            if (threadDetails.length > 1) { 
                msgSection.setCollapsible(true).setNumUncollapsibleWidgets(1); 
            }

            // 5a. Añadimos el estado "Linked" como PRIMER widget (siempre visible)
            msgSection.addWidget(
                CardService.newTextParagraph()
                .setText("<b>✅ Linked to Maatdesk</b>")
            );

            // 6a. Añadimos el "Subject" (oculto en "Show more")
            msgSection.addWidget(CardService.newTextParagraph().setText(subjectText));

            // 7a. Añadimos el botón "View" (oculto en "Show more")
            if (!isSingleAlreadyLinked) {
                const mdUrl = `${MD.APP}/matters/${encodeURIComponent(linkedMatterId)}/details/`;
                msgSection.addWidget(
                    CardService.newButtonSet()
                        .addButton(
                            CardService.newTextButton()
                                .setText("View in Maatdesk")
                                .setOpenLink(CardService.newOpenLink().setUrl(mdUrl))
                                .setTextButtonStyle(CardService.TextButtonStyle.TEXT)
                        )
                );
            }
        } else {
            // --- ESTADO NO VINCULADO ---
            
            // 4b. Hacemos que TODO sea colapsable (0 widgets visibles)
            if (threadDetails.length > 1) { 
                msgSection.setCollapsible(true).setNumUncollapsibleWidgets(0); 
            }

            // 5b. Añadimos el "Subject" PRIMERO (oculto en "Show more")
            msgSection.addWidget(CardService.newTextParagraph().setText(subjectText));

            // 6b. Añadimos el botón "Details & Link" (oculto en "Show more")
            let buttonMessageIdParam = msg.messageId;
            let isButtonDisabled = !isMatterSelected;
            
            if (!buttonMessageIdParam) {
                log_("buildCombinedViewCard_.WARNING_empty_id_for_button", { index:index });
                buttonMessageIdParam = ""; 
                isButtonDisabled = true;
            }
            msgSection.addWidget(
                CardService.newButtonSet()
                .addButton(
                    CardService.newTextButton().setText("Details & Link")
                    .setOnClickAction(
                        CardService.newAction()
                        .setFunctionName("onGoToLinkScreen_")
                        .setParameters({ messageIdHeader: buttonMessageIdParam })
                    )
                    .setTextButtonStyle(CardService.TextButtonStyle.FILLED)
                    .setDisabled(isButtonDisabled)
                )
            );
        }

        // (Adjuntos: siempre ocultos)
        if (msg.attachments && msg.attachments.length > 0) {
            msgSection.addWidget(CardService.newTextParagraph().setText(`<b>Attachments (${msg.attachments.length}):</b>`));
            msg.attachments.forEach(att => {
                msgSection.addWidget(
                    CardService.newKeyValue()
                    .setIcon(CardService.Icon.ATTACHMENT)
                    .setContent(att.filename)
                    .setBottomLabel(`~${Math.ceil(att.size / 1024)} KB`)
                );
            });
        }
        b.addSection(msgSection);
        log_("buildCombinedViewCard_.added_msg_section", { index: index });
    } catch (loopErr) {
        log_("buildCombinedViewCard_.ERROR_in_message_loop", { index: index, error: String(loopErr) });
    }
  });
  
  log_("buildCombinedViewCard_.FINISHED_MESSAGE_LOOP", {});
  log_("buildCombinedViewCard_.FINAL_BUILD", {});
  
  if (typeof applyCommonChrome_ === 'function') {
      return applyCommonChrome_(b).build();
  } else {
      return b.build();
  }
}

/**
 * Busca un objeto GmailApp.Message usando su Message-ID (header).
 * @param {string} messageIdHeader - El ID del header (ej. <CAD...>)
 * @return {GmailApp.Message|null} El objeto del mensaje o null si no se encuentra.
 */
function findMessageByHeaderId_(messageIdHeader) {
    try {
        // [cite: 388]
        const searchResults = GmailApp.search(`rfc822msgid:${messageIdHeader}`);
        if (searchResults && searchResults.length > 0) {
            const thread = searchResults[0]; // [cite: 389]
            const messagesInThread = thread.getMessages(); // [cite: 390]
            // Buscamos el mensaje específico dentro del hilo [cite: 390]
            const msg = messagesInThread.find(m => m.getHeader("Message-ID").replace(/^</, '').replace(/>$/, '').trim() === messageIdHeader);
            return msg || null;
        }
        return null;
    } catch (searchErr) {
        log_("findMessageByHeaderId_.error", { headerId: messageIdHeader, error: String(searchErr) });
        return null;
    }
}

/**
 * Se ejecuta al pulsar "Link all emails".
 * Vincula TODOS los correos NO vinculados Y sube TODOS los adjuntos del hilo.
 * ¡ESTA ES LA NUEVA FUNCIÓN QUE FALTABA!
 * @param {Object} e - El objeto del evento de la acción.
 */
function onDoLinkAllAndUpload_(e) {
  try {
    // 1. Obtener contexto (Matter, Carpeta, Hilo, Etiqueta)
    const chosenMatter = readChosenMatterFromCache_(); // [cite: 549]
    const destinationFolder = readDestinationFolderFromCache_(); // [cite: 696]
    const mailMeta = readMetadataFromCache_(); // [cite: 545] (para threadId hex)
    const threadDetails = readThreadDetailsFromCache_(); // [cite: 600] (lista de {messageId, ...})
    // Leemos la etiqueta seleccionada del formulario [cite: 258, 299]
    const labelToApply = e.formInput.selected_label || ""; 

    if (!chosenMatter || !chosenMatter.id) throw new Error("No Matter is selected.");
    if (!mailMeta || !mailMeta.threadId) throw new Error("Thread ID not found in cache.");

    // 2. Filtrar correos que YA están vinculados
    const linkedMessageData = apiGetLinkedMessages_(mailMeta.threadId); // [cite: 641]
    const linkedIdSet = new Set(linkedMessageData.map(item => item.gmailId)); // [cite: 427]
    const messagesToLink = threadDetails.filter(msg => !linkedIdSet.has(msg.messageId)); // [cite: 427]

    log_("onDoLinkAllAndUpload_.start", {
      matterId: chosenMatter.id,
      folderId: destinationFolder.id,
      label: labelToApply,
      totalInThread: threadDetails.length,
      alreadyLinked: linkedIdSet.size,
      toLink: messagesToLink.length
    });

    // 3. Vincular los correos NUEVOS (Payloads .eml)
    let linkSuccessCount = 0;
    let linkErrorCount = 0;
    const payloads = [];

    if (messagesToLink.length > 0) {
        messagesToLink.forEach(msgDetail => {
          try {
            // Usamos nuestra nueva función auxiliar
            const msg = findMessageByHeaderId_(msgDetail.messageId); 
            if (!msg) throw new Error(`Could not find message object for ${msgDetail.messageId}`);
            
            // Creamos los metadatos para este mensaje específico [cite: 398]
            const singleMailMeta = {
              threadId: msg.getThread().getId(), // [cite: 111, 398]
              sentAtIso: msg.getDate().toISOString(), // [cite: 398, 432]
              subject: msg.getSubject(), // [cite: 116, 398]
              from: msg.getFrom(), // [cite: 116, 398]
              to: msg.getTo() || "", // [cite: 116, 398]
              messageId: msgDetail.messageId // [cite: 117, 399] (El ID del header)
            };

            const emailPayload = buildGmailPayload_(msg, [], { // [cite: 654]
              includeAttachments: false, // El .eml se incluye aparte
              includeEml: true,
            }, singleMailMeta);
            
            payloads.push(emailPayload);
          } catch (err) {
            log_("onDoLinkAllAndUpload_.build_payload_error", { msgId: msgDetail.messageId, error: String(err) });
            linkErrorCount++;
          }
        });

        if (payloads.length > 0) {
          const emailBody = { matterId: chosenMatter.id, items: payloads }; // [cite: 434]
          const respEmail = callMaatdesk_( // [cite: 603]
            `/api/matters/${encodeURIComponent(chosenMatter.id)}/gmail-emails`,
            { 
              method: "post", 
              contentType: "application/json", 
              payload: JSON.stringify(emailBody) 
            }
          );
          if (respEmail.getResponseCode() >= 300) { // [cite: 436]
            throw new Error(`API Error linking emails: ${respEmail.getContentText()}`);
          }
          linkSuccessCount = payloads.length;
        }
    }
    log_("onDoLinkAllAndUpload_.linking_complete", { success: linkSuccessCount, errors: linkErrorCount });

    // 4. Subir TODOS los adjuntos de TODO el hilo
    let uploadCount = 0;
    let totalAttachmentsFound = 0;
    let uploadErrors = [];
    const uploadUrl = `${MD.API}/api/matters/${encodeURIComponent(chosenMatter.id)}/documents/file`; // [cite: 406]
    
    // Iteramos sobre TODOS los mensajes del hilo para buscar adjuntos
    for (const msgDetail of threadDetails) {
        try {
            const msg = findMessageByHeaderId_(msgDetail.messageId);
            if (!msg) continue;
            
            const attachments = msg.getAttachments() || []; // [cite: 395]
            if (attachments.length === 0) continue;

            totalAttachmentsFound += attachments.length;
            log_("onDoLinkAllAndUpload_.uploading_from_msg", { msgId: msgDetail.messageId, count: attachments.length });

            for (const fileBlob of attachments) {
                let fileName = "unknown";
                try {
                    fileName = fileBlob.getName() || `attachment_${Date.now()}`;
                    // Usamos la carpeta de destino seleccionada [cite: 408]
                    const metadata = { 
                      name: fileName, 
                      parentId: destinationFolder.id || "", 
                      description: `Uploaded from Gmail Add-on (Thread Link)` 
                    };
                    
                    const respFile = uploadFileAsMultipart_(uploadUrl, metadata, fileBlob); // [cite: 754]
            
                    if (respFile.getResponseCode() < 300) { // [cite: 409]
                        uploadCount++;
                    } else {
                        const errorResponse = respFile.getContentText();
                        log_("onDoLinkAllAndUpload_.upload_failed", { name: fileName, status: respFile.getResponseCode(), response: errorResponse });
                        uploadErrors.push(fileName);
                    }
                } catch (uploadErr) {
                     log_("onDoLinkAllAndUpload_.upload_loop_error", { name: fileName, error: String(uploadErr) });
                     uploadErrors.push(fileName);
                }
            }
        } catch (getMsgErr) {
            log_("onDoLinkAllAndUpload_.get_attachments_error", { msgId: msgDetail.messageId, error: String(getMsgErr) });
        }
    }
    log_("onDoLinkAllAndUpload_.upload_complete", { success: uploadCount, totalFound: totalAttachmentsFound, errors: uploadErrors.length });

    // 5. Aplicar etiqueta (si se seleccionó)
    // Solo la aplicamos si hicimos alguna acción (vincular o subir)
    if (labelToApply && (linkSuccessCount > 0 || uploadCount > 0)) {
        log_("onDoLinkAllAndUpload_.applying_label", { label: labelToApply, threadId: mailMeta.threadId });
        applyGmailLabel_(mailMeta.threadId, labelToApply); // [cite: 86, 413]
    }

    // 6. Mostrar tarjeta de éxito
    let successMessage = `Operation Complete.<br>`;
    if (messagesToLink.length > 0) {
        successMessage += `<b>${linkSuccessCount} of ${messagesToLink.length}</b> new email(s) linked.<br>`;
    } else {
        successMessage += `All emails were already linked.<br>`;
    }
    
    if (totalAttachmentsFound > 0) {
        successMessage += `<b>${uploadCount} of ${totalAttachmentsFound}</b> attachments uploaded.`;
        if (uploadErrors.length > 0) {
            successMessage += ` (${uploadErrors.length} upload error(s)).`;
        }
    } else {
        successMessage += `No attachments found in this thread.`;
    }

    const successCard = buildSuccessCard_(successMessage); // [cite: 532]
    // Usamos updateCard para reemplazar la vista actual
    const nav = CardService.newNavigation().updateCard(successCard); 
    return CardService.newActionResponseBuilder().setNavigation(nav).build();

  } catch (err) {
    // Capturamos cualquier error fatal
    log_("onDoLinkAllAndUpload_.FATAL_ERROR", { errorMessage: String(err), stack: err.stack });
    if (String(err.message).includes("SESSION_EXPIRED")) { // [cite: 420]
        throw err; // Relanzamos el error de sesión
    }
    // Mostramos un toast para cualquier otro error
    return buildToast_(`❌ An error occurred: ${err.message}`); // [cite: 421]
  }
}

/**
 * Se ejecuta al pulsar "Details & Link".
 * Guarda messageId (header) Y la etiqueta seleccionada en caché.
 */
function onGoToLinkScreen_(e) {
  try {
    // Leemos el ID del HEADER del parámetro del botón
    const messageIdHeader = e.parameters.messageIdHeader;
    if (!messageIdHeader) throw new Error("messageIdHeader parameter is missing.");

    // ¡¡NUEVO!! Leemos la etiqueta seleccionada del formulario de la pantalla anterior
    const labelToApply = e.formInput.selected_label || ""; // Lee el valor del dropdown
    log_("onGoToLinkScreen_.received_data", { headerId: messageIdHeader, label: labelToApply });

    // Guardamos AMBOS valores en caché para la siguiente pantalla
    const cache = CacheService.getUserCache();
    cache.put('current_linking_messageIdHeader', messageIdHeader, 1800);
    cache.put('current_linking_label', labelToApply, 1800); // Guarda la etiqueta

    log_("onGoToLinkScreen_.nav", { msgIdHeader: messageIdHeader, label: labelToApply });

    // Construimos la tarjeta de detalles pasándole el ID del HEADER
    const card = buildLinkSingleEmailCard_(messageIdHeader);
    const nav = CardService.newNavigation().pushCard(card);
    return CardService.newActionResponseBuilder().setNavigation(nav).build();

  } catch (err) {
    log_("onGoToLinkScreen_.error", String(err));
    return buildToast_("Could not load email details: " + err.message);
  }
}

/**
 * Construye la tarjeta de "detalles".
 * ¡VERSIÓN FINAL v6! Vuelve a incluir la comprobación de permisos.
 */
function buildLinkSingleEmailCard_(messageIdHeader) {
  log_("buildLinkSingleEmailCard_.start", { messageIdHeader: messageIdHeader });
  const allDetails = readThreadDetailsFromCache_();
  const msgData = allDetails.find(m => m.messageId === messageIdHeader);

  if (!msgData) {
      log_("buildLinkSingleEmailCard_.error_not_found_in_cache", { searchHeaderId: messageIdHeader });
      throw new Error(`Message data for ${messageIdHeader} not found in cached thread details.`);
  }

  const b = CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader().setTitle("Link Email to Matter"));

  // --- Sección Matter ---
  let chosenMatter = readChosenMatterFromCache_();
  const isMatterSelected = !!(chosenMatter && chosenMatter.id);
  const matterDisplaySection = CardService.newCardSection();

  if (isMatterSelected) {
      matterDisplaySection.addWidget(
        CardService.newKeyValue()
          .setTopLabel("Matter")
          .setContent(chosenMatter.label || chosenMatter.id)
          .setIcon(CardService.Icon.BOOKMARK)
          .setButton(
             CardService.newTextButton()
                .setText("CHANGE")
                .setOnClickAction(
                    CardService.newAction().setFunctionName("onEditMatterOnDetailScreen_")
                )
                .setTextButtonStyle(CardService.TextButtonStyle.TEXT)
          )
      );
  } else {
      matterDisplaySection.setHeader("Select a Matter");
      let suggestions = [];
      try { suggestions = JSON.parse(userProps_().getProperty(PROPS.LAST_SUGGESTED_LIST) || "[]"); } catch (_) {}
      if (suggestions && suggestions.length > 0) {
        const dd = CardService.newSelectionInput()
          .setType(CardService.SelectionInputType.DROPDOWN)
          .setFieldName("detail_suggested_matter")
          .setOnChangeAction(CardService.newAction().setFunctionName("onDetailMatterChange_"))
          .addItem("— Select from suggestions —", "", true);
        suggestions.forEach(it => dd.addItem(it.label, String(it.id), false));
        matterDisplaySection.addWidget(dd);
      }
      const ti = CardService.newTextInput()
        .setFieldName("detail_search_q")
        .setTitle("Or search Matter")
        .setHint("Type to see suggestions…")
        .setSuggestionsAction(CardService.newAction().setFunctionName("onMatterSearchSuggest_"))
        .setOnChangeAction(CardService.newAction().setFunctionName("onDetailMatterChange_"));
      matterDisplaySection.addWidget(ti);
  }
  b.addSection(matterDisplaySection);

  // --- Sección Info Correo (Sin cambios) ---
  const date = new Date(msgData.date).toLocaleString();
  const from = (msgData.from || "").replace(/<.*?>/g, "").trim();
  b.addSection(
    CardService.newCardSection()
      .addWidget(CardService.newKeyValue().setTopLabel("From").setContent(from))
      .addWidget(CardService.newKeyValue().setTopLabel("Date").setContent(date))
      .addWidget(
        CardService.newKeyValue()
          .setTopLabel("Subject")
          .setContent(msgData.subject || "(No Subject)")
          .setMultiline(true)
      )
  );

  // --- ¡MODIFICADO! Secciones condicionales ---
  // Solo mostramos estas secciones si ya se ha seleccionado un Matter.
  let hasDocPermission = false; // Por defecto no hay permiso
  
  if (isMatterSelected) {
    // --- Sección Etiquetado ---
    const cachedLabel = CacheService.getUserCache().get('current_linking_label');
    const labelDropdown = CardService.newSelectionInput()
      .setType(CardService.SelectionInputType.DROPDOWN)
      .setFieldName("selected_label");
    labelDropdown.addItem("— Do not apply label —", "", !cachedLabel);
    try {
      const labels = GmailApp.getUserLabels();
      labels.forEach(label => {
        const isSelected = (!!cachedLabel && label.getName() === cachedLabel);
        labelDropdown.addItem(label.getName(), label.getName(), isSelected);
      });
    } catch (e) { log_('buildCard.getLabels.error', String(e)); }
    b.addSection(
        CardService.newCardSection()
        .setHeader("Labeling Options")
        .addWidget(labelDropdown)
    );

    // --- ¡NUEVO! Comprobamos permisos ANTES de mostrar adjuntos/carpetas ---
    hasDocPermission = apiCheckDocumentPermission_();
    log_('buildLinkSingleEmailCard_.permission_check', { hasPermission: hasDocPermission });

    const hasAttachments = msgData.attachments && msgData.attachments.length > 0;
    
    // Mostramos secciones de adjuntos y carpetas SÓLO si tiene permisos Y hay adjuntos
    if (hasDocPermission && hasAttachments) {
        const attSection = CardService.newCardSection().setHeader("Select attachments to upload");
        const attCheckboxes = CardService.newSelectionInput()
            .setType(CardService.SelectionInputType.CHECK_BOX)
            .setFieldName("attachments_to_save");
        msgData.attachments.forEach((att, index) => {
            const label = `${att.filename} (~${Math.ceil(att.size / 1024)} KB)`;
            attCheckboxes.addItem(label, String(index), true); 
        });
        attSection.addWidget(attCheckboxes);
        b.addSection(attSection);

        // (Sección de Carpeta)
        const destinationFolder = readDestinationFolderFromCache_();
        let folderDisplayName = `🏠 ${destinationFolder.name}`;
        if (destinationFolder.path && destinationFolder.path !== "/") {
            let fullPathWithIcon = `🏠${destinationFolder.path}`;
            const MAX_PATH_LENGTH = 35;
            if (fullPathWithIcon.length > MAX_PATH_LENGTH) {
                folderDisplayName = `🏠.../${destinationFolder.name}`;
            } else {
                folderDisplayName = fullPathWithIcon;
            }
        }
        b.addSection(
            CardService.newCardSection()
            .setHeader("Destination Folder")
            .addWidget(
                CardService.newKeyValue()
                .setContent(folderDisplayName)
                .setButton(
                     CardService.newTextButton()
                    .setText("CHANGE")
                    .setOnClickAction(
                        CardService.newAction()
                          .setFunctionName("onSelectFolderClick_")
                          .setParameters({ origin: 'detail' })
                    )
                    .setTextButtonStyle(CardService.TextButtonStyle.TEXT)
                )
            )
        );
    } else if (hasAttachments) {
        // Si hay adjuntos pero NO hay permisos, mostramos el aviso
        b.addSection(
            CardService.newCardSection()
            .setHeader("Attachments")
            .addWidget(
                CardService.newTextParagraph()
                .setText("You don’t have permission to upload documents for this matter.")
            )
        );
    }
  } // --- Fin de if(isMatterSelected) ---

  // --- Botón Acción Final ---
  // ¡MODIFICADO! El texto del botón ahora depende de los permisos
  const hasAttachments = msgData.attachments && msgData.attachments.length > 0;
  const buttonText = (isMatterSelected && hasAttachments && hasDocPermission) ?
    "LINK EMAIL & UPLOAD" : "LINK THIS EMAIL";
    
  b.addSection(
    CardService.newCardSection()
      .addWidget(
        CardService.newTextButton()
          .setText(buttonText)
          .setOnClickAction(
            CardService.newAction().setFunctionName("onDoLinkSingleEmail_")
          )
          .setTextButtonStyle(CardService.TextButtonStyle.FILLED)
          .setBackgroundColor('#3ED79F')
          .setDisabled(!isMatterSelected) // Habilitado solo si hay Matter
      )
  );

  return b.build();
}

/**
 * Se ejecuta cuando el usuario selecciona un Matter (dropdown o búsqueda)
 * DENTRO de la pantalla de detalles de un solo correo.
 * (Esta es la función que faltaba)
 */
function onDetailMatterChange_(e) {
  try {
    const inputs = e?.commonEventObject?.formInputs || {};
    const selId = inputs.detail_suggested_matter?.stringInputs?.value?.[0] || "";
    const qTxt = (inputs.detail_search_q?.stringInputs?.value?.[0] || "").trim();

    // --- Lógica para encontrar y guardar el Matter ---
    let chosen = null;
    if (selId) { 
      let suggestions = [];
      try { suggestions = JSON.parse(userProps_().getProperty(PROPS.LAST_SUGGESTED_LIST) || "[]"); } catch (_) {} 
      chosen = suggestions.find((s) => String(s.id) === String(selId));
    } else if (qTxt) { 
      let cache = [];
      try { cache = JSON.parse(userProps_().getProperty(PROPS.LAST_SEARCH_SUGGESTIONS) || "[]"); } catch (_) {} 
      chosen = cache.find((x) => x.label === qTxt);
    }

    if (chosen) { 
      saveChosenMatterToCache_(chosen); 
      log_("onDetailMatterChange_.saved_matter", chosen);
    } else {
      log_("onDetailMatterChange_.no_matter_saved", { selId: selId, qTxt: qTxt });
    }

    // Leemos el messageId que teníamos guardado (con el nombre correcto)
    const messageIdHeader = CacheService.getUserCache().get('current_linking_messageIdHeader');

    if (!messageIdHeader) throw new Error("Linking messageIdHeader missing from cache.");

    // Reconstruimos la tarjeta de detalles (ahora el botón estará habilitado)
    const card = buildLinkSingleEmailCard_(messageIdHeader);

    // Actualizamos la tarjeta actual
    return CardService.newActionResponseBuilder() 
      .setNavigation(CardService.newNavigation().updateCard(card))
      .build();

  } catch (err) {
    log_("onDetailMatterChange_.error", String(err));
    return buildToast_("Could not update Matter selection.");
  }
}

/**
 * Loguea un objeto JSON grande dividiéndolo en partes si es necesario.
 * @param {string} tag - La etiqueta para el log.
 * @param {Object} obj - El objeto a loguear.
 * @param {number} [maxLen=8192] - Longitud máxima por parte.
 */
function logPartitioned_(tag, obj, maxLen = 8192) {
  try {
    const userEmail = Session.getActiveUser().getEmail();
    const scrub = (v) => typeof v === "string" && v.length > 16 ? v.slice(0, 6) + "…" + v.slice(-4) : v;
    const safeJson = JSON.stringify(obj, (k, v) => /^(access_token|refresh_token|id_token|authorization|contentBase64)$/i.test(k) ? scrub(v) : v);
    const totalLen = safeJson.length;

    if (totalLen <= maxLen) {
      console.log(`[MD][${userEmail}][${tag}] ${safeJson}`);
    } else {
      const numParts = Math.ceil(totalLen / maxLen);
      for (let i = 0; i < numParts; i++) {
        const start = i * maxLen;
        const end = start + maxLen;
        const part = safeJson.substring(start, end);
        console.log(`[MD][${userEmail}][${tag}] [${i + 1}/${numParts}] ${part}`);
      }
    }
  } catch (e) {
    console.log(`[MD][${Session.getActiveUser().getEmail()}][${tag}] Error partitioning log: ${String(e)}`, obj);
  }
}

/**
 * Guarda los detalles del hilo (array de mensajes) en la caché del usuario.
 * @param {Array<Object>} details - El array de objetos de mensaje.
 */
function saveThreadDetailsToCache_(details) {
  try {
    const key = "current_thread_details";
    // Aseguramos que 'details' sea un array antes de guardar
    const detailsToSave = Array.isArray(details) ? details : [];
    CacheService.getUserCache().put(key, JSON.stringify(detailsToSave), 1800); // 30 min
    log_("cache.thread_details_saved", { count: detailsToSave.length });
  } catch (e) {
    log_("cache.thread_details_save_error", { error: String(e) });
  }
}

/**
 * ¡FUNCIÓN DE VINCULACIÓN INDIVIDUAL (COMPLETA Y FINAL v4)!
 * Lee ID Header de caché y lo envía DIRECTAMENTE a la API.
 */
function onDoLinkSingleEmail_(e) {
  try {
    // 1. Obtener contexto
    const cache = CacheService.getUserCache();
    // Leemos el ID del HEADER de la caché
    const messageIdHeader = cache.get('current_linking_messageIdHeader');
    const chosenMatter = readChosenMatterFromCache_();
    const mailMeta = readMetadataFromCache_(); // Contiene threadId (hex)
    const destinationFolder = readDestinationFolderFromCache_();

    // 1. Primero, intentamos leer la etiqueta guardada en caché (la de la pantalla 1)
    let labelToApply = cache.get('current_linking_label');
    
    // 2. Si no había etiqueta en caché, intentamos leerla del formulario actual (pantalla 2)
    if (!labelToApply) {
        labelToApply = e.formInput.selected_label || "";
    }

    // Verificaciones
    if (!messageIdHeader) throw new Error("Linking Message ID (Header) not found in cache.");
    if (!chosenMatter || !chosenMatter.id) throw new Error("Chosen Matter not found in cache.");
    if (!mailMeta || !mailMeta.threadId) throw new Error("Thread ID not found in cache (mailMeta).");

    log_("onDoLinkSingleEmail_.start", { msgIdHeader: messageIdHeader, matterId: chosenMatter.id, label: labelToApply });

    // 2. Obtener el objeto GmailApp.Message (Necesitamos buscarlo)
    // Usamos GmailApp.search porque getMessageById no funciona con el header ID
    let msg = null;
    try {
        const searchResults = GmailApp.search(`rfc822msgid:${messageIdHeader}`);
        if (searchResults && searchResults.length > 0) {
            const thread = searchResults[0];
            const messagesInThread = thread.getMessages();
            // Buscamos el mensaje específico dentro del hilo
            msg = messagesInThread.find(m => m.getHeader("Message-ID").replace(/^</, '').replace(/>$/, '').trim() === messageIdHeader);
        }
        if (!msg) {
             throw new Error(`GmailApp.search found no reliable message for Header ID: ${messageIdHeader}`);
        }
        log_("onDoLinkSingleEmail_.found_message_object", { headerId: messageIdHeader });
    } catch (searchErr) {
        log_("onDoLinkSingleEmail_.ERROR_finding_message_object", { headerId: messageIdHeader, error: String(searchErr) });
        throw new Error(`Failed to retrieve message object for ${messageIdHeader}: ${searchErr.message}`);
    }

    // 3. Obtener adjuntos del objeto 'msg'
    const allAttachments = msg.getAttachments() || [];

    // 4. Obtener adjuntos seleccionados del formulario
    const formValue = e.formInput.attachments_to_save;
    const selectedIndexes = !formValue ? [] : [].concat(formValue);
    log_("onDoLinkSingleEmail_.attachments", { selected: selectedIndexes.length, total: allAttachments.length });

    // 5. Construir payload .eml (¡¡USA messageIdHeader y mailMeta.threadId!!)
    const singleMailMeta = {
      threadId: mailMeta.threadId,        // Hex ID del hilo
      sentAtIso: msg.getDate().toISOString(), // Usamos la fecha real del mensaje actual
      subject: msg.getSubject(),
      from: msg.getFrom(),
      to: msg.getTo() || "",
      messageId: messageIdHeader         // ID del mensaje (¡Header ID!)
    };

    // Llamamos a buildGmailPayload_ (que enviará gmailId=HeaderID, threadId=Hex)
    const emailPayloadItem = buildGmailPayload_(msg, [], {
      includeAttachments: false, // El .eml se incluye aparte
      includeEml: true,
    }, singleMailMeta);

    const emailBody = { matterId: chosenMatter.id, items: [emailPayloadItem] };
    logPartitioned_("onDoLinkSingleEmail_.PAYLOAD_TO_API", emailBody); // Logueamos el payload

    // 6. Vincular email (llamada API)
    const respEmail = callMaatdesk_(
      `/api/matters/${encodeURIComponent(chosenMatter.id)}/gmail-emails`,
      {
        method: "post",
        contentType: "application/json",
        payload: JSON.stringify(emailBody),
      }
    );
    // Verificamos la respuesta
    if (respEmail.getResponseCode() >= 300) {
      log_("onDoLinkSingleEmail_.link_email_failed", { status: respEmail.getResponseCode(), response: respEmail.getContentText() });
      throw new Error(`Failed to link email: ${respEmail.getContentText()}`);
    }
    log_("onDoLinkSingleEmail_.link_email_success", { status: respEmail.getResponseCode() });

    // 7. Subir adjuntos seleccionados
    let uploadCount = 0; let uploadErrors = [];
    if (selectedIndexes.length > 0) {
        const uploadUrl = `${MD.API}/api/matters/${encodeURIComponent(chosenMatter.id)}/documents/file`;
        log_("onDoLinkSingleEmail_.upload_starting", { count: selectedIndexes.length, url: uploadUrl });
        selectedIndexes.forEach(indexStr => {
            let fileName = "unknown";
            try {
                const idx = parseInt(indexStr, 10);
                const fileBlob = allAttachments[idx];
                if (!fileBlob) { throw new Error(`Blob at index ${idx} not found.`); }
                fileName = fileBlob.getName() || `attachment_${idx}`;
                const metadata = { name: fileName, parentId: destinationFolder.id || "", description: `Uploaded from Gmail Add-on` };
                log_("onDoLinkSingleEmail_.uploading", metadata);
                const respFile = uploadFileAsMultipart_(uploadUrl, metadata, fileBlob);
                if (respFile.getResponseCode() < 300) {
                    uploadCount++; log_("onDoLinkSingleEmail_.upload_success", { name: fileName });
                } else {
                    const errorResponse = respFile.getContentText();
                    log_("onDoLinkSingleEmail_.upload_failed", { name: fileName, status: respFile.getResponseCode(), response: errorResponse });
                    uploadErrors.push(`${fileName}: Failed (Status ${respFile.getResponseCode()})`);
                }
            } catch (uploadErr) {
                log_("onDoLinkSingleEmail_.upload_loop_error", { name: fileName, error: String(uploadErr) });
                uploadErrors.push(`${fileName}: Error (${uploadErr.message})`);
            }
        });
        log_("onDoLinkSingleEmail_.upload_finished", { success: uploadCount, errors: uploadErrors.length });
    }

    // 8. Aplicar etiqueta (usa mailMeta.threadId - hex)
    if (labelToApply) {
      log_("onDoLinkSingleEmail_.applying_label", { label: labelToApply, threadId: mailMeta.threadId });
      applyGmailLabel_(mailMeta.threadId, labelToApply);
    }

    // 9. Mostrar tarjeta de éxito
    let successMessage = `✅ Email "<b>${msg.getSubject()}</b>" linked successfully.`;
    if (selectedIndexes.length > 0) {
      successMessage += `<br>Uploaded <b>${uploadCount} of ${selectedIndexes.length}</b> selected attachments.`;
      if (uploadErrors.length > 0) { successMessage += ` (${uploadErrors.length} error(s)).`; }
    } else if (allAttachments.length > 0) {
      successMessage += `<br>No attachments were selected for upload.`;
    }
    const successCard = buildSuccessCard_(successMessage);
    const nav = CardService.newNavigation().updateCard(successCard);
    return CardService.newActionResponseBuilder().setNavigation(nav).build();

  } catch (err) {
    // Capturamos errores generales
    log_("onDoLinkSingleEmail_.error", { errorMessage: String(err), stack: err.stack }); // Loguea el error completo
    // Si es error de sesión, lo relanzamos
    if (String(err.message).includes("SESSION_EXPIRED")) {
        throw err;
    }
    // Para otros errores, mostramos un Toast
    return buildToast_(`❌ An error occurred: ${err.message}`);
  }
}

/**
 * Se ejecuta al pulsar "CHANGE" en la pantalla de detalles.
 * Borra el matter de la caché y recarga la tarjeta para volver a mostrar
 * los controles de selección de Matter.
 */
function onEditMatterOnDetailScreen_(e) {
  try {
    // 1. Borramos el matter guardado
    CacheService.getUserCache().remove('current_matter_meta');
    log_("onEditMatterOnDetailScreen_.cleared_matter_cache", {});

    // 2. Leemos el ID del email que estábamos viendo
    const messageIdHeader = CacheService.getUserCache().get('current_linking_messageIdHeader');
    if (!messageIdHeader) {
      throw new Error("Linking messageIdHeader missing from cache.");
    }

    // 3. Reconstruimos la tarjeta de detalles (ahora sin Matter preseleccionado)
    const card = buildLinkSingleEmailCard_(messageIdHeader);

    // 4. Actualizamos la vista
    const nav = CardService.newNavigation().updateCard(card);
    return CardService.newActionResponseBuilder().setNavigation(nav).build();

  } catch (err) {
    log_("onEditMatterOnDetailScreen_.error", String(err));
    return buildToast_("Could not reload Matter selection.");
  }
}

/**
 * Se ejecuta al pulsar "Link all emails".
 * ¡VERSIÓN FINAL! Vincula solo los correos NO vinculados.
 */
function onLinkAllEmails_(e) {
  try {
   /*  ensurePinFromSession_(); */
    
    // 1. Obtener los datos necesarios
    const chosenMatter = readChosenMatterFromCache_();
    const mailMeta = readMetadataFromCache_();
    const threadDetails = readThreadDetailsFromCache_();
    const labelToApply = e.formInput.selected_label || "";

    // 2. ¡¡AQUÍ ESTÁ EL CAMBIO!!
    // Llamamos a la API para ver qué hay ya vinculado
    const linkedMessageIds = apiGetLinkedMessages_(mailMeta.threadId);
    const linkedIdSet = new Set(linkedMessageIds);

    // ¡Filtramos! Solo procesamos los que NO están en el Set
    const messagesToLink = threadDetails.filter(msg => !linkedIdSet.has(msg.messageId));
    
    log_("onLinkAllEmails_.start", { 
      totalInThread: threadDetails.length,
      alreadyLinked: linkedIdSet.size,
      toLink: messagesToLink.length,
      matterId: chosenMatter.id, 
      label: labelToApply 
    });

    // Si no hay nada que vincular, terminamos con éxito
    if (messagesToLink.length === 0) {
      return buildToast_("✅ All emails in this thread are already linked.");
    }

    let successCount = 0;
    let errorCount = 0;
    const payloads = [];

    // 3. Construir payloads (solo para los correos nuevos)
    messagesToLink.forEach(msgDetail => {
      try {
        const msg = GmailApp.getMessageById(msgDetail.messageId);
        
        const singleMailMeta = {
          ...mailMeta,
          subject: msg.getSubject(),
          from: msg.getFrom(),
          to: msg.getTo() || "",
          sentAtIso: msg.getDate().toISOString(),
          messageId: msgDetail.messageId
        };

        const emailPayload = buildGmailPayload_(msg, [], {
          includeAttachments: false,
          includeEml: true,
        }, singleMailMeta);
        
        payloads.push(emailPayload);
      } catch (err) {
        log_("onLinkAllEmails_.build_payload_error", String(err));
        errorCount++;
      }
    });

    // 4. Enviar payloads
    if (payloads.length > 0) {
      const emailBody = { matterId: chosenMatter.id, items: payloads };
      
      const respEmail = callMaatdesk_(
        `/api/matters/${encodeURIComponent(chosenMatter.id)}/gmail-emails`,
        {
          method: "post",
          contentType: "application/json",
          payload: JSON.stringify(emailBody),
        },
      );

      if (respEmail.getResponseCode() >= 300) {
        throw new Error(`API Error: ${respEmail.getContentText()}`);
      }
      successCount = payloads.length;
    }

    // 5. Aplicar la etiqueta
    if (labelToApply && successCount > 0) {
      applyGmailLabel_(mailMeta.threadId, labelToApply);
    }
    
    // 6. Mostrar tarjeta de éxito
    const successMessage = `✅ Linked <b>${successCount} new email(s)</b>. ${errorCount} failed.`;
    const successCard = buildSuccessCard_(successMessage);
    const nav = CardService.newNavigation().updateCard(successCard);
    return CardService.newActionResponseBuilder().setNavigation(nav).build();

  } catch (err) {
    log_("onLinkAllEmails_.error", String(err));
    return buildToast_(`❌ Could not link emails: ${err.message}`);
  }
}

/**
 * Se ejecuta cuando el usuario selecciona un Matter (dropdown o búsqueda)
 * en la nueva tarjeta combinada.
 * Guarda la elección en caché y recarga la tarjeta para habilitar los botones.
 */
/* function onCombinedStateChange_(e) {
  try {
    const inputs = e?.commonEventObject?.formInputs || {};
    const selId = inputs.suggested_matter?.stringInputs?.value?.[0] || "";
    const qTxt = (inputs.search_q?.stringInputs?.value?.[0] || "").trim();
    
    const uiState = { suggestedId: selId, searchText: qTxt };
    
    // --- Lógica para encontrar y guardar el Matter ---
    let chosen = null;
    let suggestions = []; // Definimos 'suggestions' aquí
    
    try {
      // Leemos las sugerencias que guardamos al abrir el add-on
      suggestions = JSON.parse(
        userProps_().getProperty(PROPS.LAST_SUGGESTED_LIST) || "[]",
      );
    } catch (_) {}

    if (selId) {
      const foundSuggestion = suggestions.find((s) => String(s.id) === String(selId));
      if (foundSuggestion) {
          chosen = foundSuggestion; // 'foundSuggestion' ya tiene {id, label}
      }
      
    } else if (qTxt) {
      // Esta lógica es para el autocompletar de la búsqueda
      let cache = [];
      try {
        cache = JSON.parse(
          userProps_().getProperty(PROPS.LAST_SEARCH_SUGGESTIONS) || "[]",
        );
      } catch (_) {}
      chosen = cache.find((x) => x.label === qTxt);
    }
    
    // ¡Paso clave! Si encontramos un Matter, lo guardamos en caché
    if (chosen) {
      saveChosenMatterToCache_(chosen);
      log_("onCombinedStateChange_.saved_matter", chosen); // ¡Log de depuración!
    } else {
      log_("onCombinedStateChange_.no_matter_saved", { selId: selId, qTxt: qTxt });
    }
    // --- Fin lógica de guardado ---

    // Leemos los datos que ya teníamos
    const details = readThreadDetailsFromCache_();
    // (Ya hemos leído las 'suggestions' arriba)
    const linkedMessageIds = apiGetLinkedMessages_(details.length > 0 ? details[0].threadId : "");

    // Volvemos a construir la misma tarjeta, pero con el nuevo estado
    const card = buildCombinedViewCard_(uiState, details, suggestions, linkedMessageIds);

    return CardService.newActionResponseBuilder()
      .setNavigation(CardService.newNavigation().updateCard(card))
      .build();
      
  } catch (err) {
    log_("onCombinedStateChange_.error", String(err));
    return buildToast_("Could not update selection.");
  }
} */

/**
 * Se ejecuta cuando el usuario selecciona un Matter del dropdown de sugerencias.
 * Limpia el campo de búsqueda de texto.
 */
function onSuggestionDropdownChange_(e) {
  try {
    const inputs = e?.commonEventObject?.formInputs || {};
    // 1. Obtenemos el valor del dropdown
    const selId = inputs.suggested_matter?.stringInputs?.value?.[0] || "";
    // 2. Creamos el estado de la UI, FORZANDO el searchText a estar vacío
    const uiState = { suggestedId: selId, searchText: "" }; 

    // --- Lógica para guardar el Matter (copiada de la función anterior) ---
    let chosen = null;
    if (selId) {
      let suggestions = [];
      try { suggestions = JSON.parse(userProps_().getProperty(PROPS.LAST_SUGGESTED_LIST) || "[]"); } catch (_) {}
      chosen = suggestions.find((s) => String(s.id) === String(selId));
      if (chosen) {
        saveChosenMatterToCache_(chosen);
        log_("onSuggestionDropdownChange_.saved_matter", chosen);
      }
    }
    // --- Fin de la lógica de guardado ---

    // Recargamos la tarjeta principal con el nuevo estado
    const details = readThreadDetailsFromCache_();
    let suggestions = [];
    try { suggestions = JSON.parse(userProps_().getProperty(PROPS.LAST_SUGGESTED_LIST) || "[]"); } catch (_) {}
    const linkedMessageIds = apiGetLinkedMessages_(details.length > 0 ? details[0].threadId : "");
    
    const card = buildCombinedViewCard_(uiState, details, suggestions, linkedMessageIds);
    return CardService.newActionResponseBuilder()
      .setNavigation(CardService.newNavigation().updateCard(card))
      .build();

  } catch (err) {
    log_("onSuggestionDropdownChange_.error", String(err));
    return buildToast_("Could not update selection.");
  }
}

/**
 * Se ejecuta cuando el usuario escribe en el campo de búsqueda.
 * Limpia la selección del dropdown.
 */
function onSearchTextChange_(e) {
  try {
    const inputs = e?.commonEventObject?.formInputs || {};
    // 1. Obtenemos el valor del campo de texto
    const qTxt = (inputs.search_q?.stringInputs?.value?.[0] || "").trim();
    // 2. Creamos el estado de la UI, FORZANDO el suggestedId a estar vacío
    const uiState = { suggestedId: "", searchText: qTxt }; 

    // --- Lógica para guardar el Matter (copiada de la función anterior) ---
    let chosen = null;
    if (qTxt) {
      let cache = [];
      try { cache = JSON.parse(userProps_().getProperty(PROPS.LAST_SEARCH_SUGGESTIONS) || "[]"); } catch (_) {}
      chosen = cache.find((x) => x.label === qTxt);
      if (chosen) {
        saveChosenMatterToCache_(chosen);
        log_("onSearchTextChange_.saved_matter", chosen);
      }
    }
    // --- Fin de la lógica de guardado ---

    // Recargamos la tarjeta principal con el nuevo estado
    const details = readThreadDetailsFromCache_();
    let suggestions = [];
    try { suggestions = JSON.parse(userProps_().getProperty(PROPS.LAST_SUGGESTED_LIST) || "[]"); } catch (_) {}
    const linkedMessageIds = apiGetLinkedMessages_(details.length > 0 ? details[0].threadId : "");

    const card = buildCombinedViewCard_(uiState, details, suggestions, linkedMessageIds);
    return CardService.newActionResponseBuilder()
      .setNavigation(CardService.newNavigation().updateCard(card))
      .build();

  } catch (err) {
    log_("onSearchTextChange_.error", String(err));
    return buildToast_("Could not update selection.");
  }
}

function onLinkAndUpload_(e) {
  try {
    ensureGmailToken_(e);
    const chosenMatter = readChosenMatterFromCache_();
    const destinationFolder = readDestinationFolderFromCache_();
    const mailMeta = readMetadataFromCache_();
    const { msg, items } = getCurrentMessageAndAttachments_(e);
    const formInputs = e?.commonEventObject?.formInputs || {};
    const selectedIndexes = getSelectedAttachmentIndexes_(
      formInputs,
      items.length,
    );

    // --- PASO 1: Vincular el correo (.eml) SIN los otros adjuntos ---
    log_("upload.step1.linking_email", { matterId: chosenMatter.id });

    const emailPayloadItem = buildGmailPayload_(msg, [], {
      includeAttachments: false,
      includeEml: true,
    },mailMeta);
    const emailBody = { matterId: chosenMatter.id, items: [emailPayloadItem] };

    const respEmail = callMaatdesk_(
      `/api/matters/${encodeURIComponent(chosenMatter.id)}/gmail-emails`,
      {
        method: "post",
        contentType: "application/json",
        payload: JSON.stringify(emailBody),
      },
    );

    if (respEmail.getResponseCode() >= 300) {
      throw new Error(`Failed to link email: ${respEmail.getContentText()}`);
    }
    log_("upload.step1.link_success", {});

    // --- PASO 2: Subir los adjuntos seleccionados uno por uno (si los hay) ---
    if (selectedIndexes.length > 0) {
      const allAttachments = msg.getAttachments({
        includeInlineImages: true,
        includeAttachments: true,
      });
      let uploadCount = 0;

      selectedIndexes.forEach((idx) => {
        const fileBlob = allAttachments[idx];
        const metadata = {
          name: fileBlob.getName(),
          parentId: destinationFolder.id, // ID de la carpeta de destino (null si es la raíz)
          description: `Uploaded from Gmail Add-on on ${new Date().toLocaleDateString()}`,
        };

        log_("upload.step2.uploading_file", metadata);
        const url = `${MD.API}/api/matters/${encodeURIComponent(chosenMatter.id)}/documents/file`;
        const respFile = uploadFileAsMultipart_(url, metadata, fileBlob);

        if (respFile.getResponseCode() < 300) {
          uploadCount++;
        } else {
          log_("upload.step2.file_upload_failed", {
            name: fileBlob.getName(),
            status: respFile.getResponseCode(),
            response: respFile.getContentText(),
          });
        }
      });

      // --- PASO 3: Mostrar tarjeta de éxito final con resumen ---
      const successMessage = `✅ Email linked successfully. ${uploadCount} of ${selectedIndexes.length} attachments uploaded.`;
      const nav = CardService.newNavigation().updateCard(
        buildSuccessCard_(successMessage),
      );
      return CardService.newActionResponseBuilder().setNavigation(nav).build();
    } else {
      // --- PASO 3 (Alternativo): Éxito sin adjuntos ---
      const successMessage = `✅ Email linked successfully. No attachments were selected to upload.`;
      const nav = CardService.newNavigation().updateCard(
        buildSuccessCard_(successMessage),
      );
      return CardService.newActionResponseBuilder().setNavigation(nav).build();
    }
  } catch (err) {
    log_("onLinkAndUpload_.error", String(err));
    return buildToast_(`❌ An error occurred, could not link to MaatDesk`);
  }
}

/* ========= 6) Constructores de UI (Cards) ========= */
function applyCommonChrome_(b) {
  return b.addCardAction(
    CardService.newCardAction()
      .setText("Sign out")
      .setOnClickAction(
        CardService.newAction().setFunctionName("onLogoutClick_"),
      ),
  );
}
function buildConnectCard_(msg) {
  const b = CardService.newCardBuilder().setHeader(
    CardService.newCardHeader().setTitle("Connect to Maatdesk"),
  );
  const mainSection = CardService.newCardSection();
  if (msg) {
    mainSection.addWidget(CardService.newTextParagraph().setText(msg));
  }
  mainSection.addWidget(
    CardService.newTextButton()
      .setText("Connect to Maatdesk")
      .setOnClickAction(
        CardService.newAction().setFunctionName("onConnectClick_"),
      )
      .setTextButtonStyle(CardService.TextButtonStyle.FILLED),
  );
  mainSection.addWidget(
    CardService.newTextButton()
      .setText("Refresh my status")
      .setOnClickAction(
        CardService.newAction().setFunctionName("onCheckSession_"),
      )
      .setTextButtonStyle(CardService.TextButtonStyle.TEXT),
  );
  b.addSection(mainSection);
  return b.build();
}
function buildFinalizingCard_() {
  const b = CardService.newCardBuilder().setHeader(
    CardService.newCardHeader().setTitle("Finalizing Connection..."),
  );
  b.addSection(
    CardService.newCardSection()
      .addWidget(
        CardService.newTextParagraph().setText(
          "You have successfully signed in.",
        ),
      )
      .addWidget(
        CardService.newTextButton()
          .setText("SHOW ADD-ON")
          .setTextButtonStyle(CardService.TextButtonStyle.FILLED)
          .setOnClickAction(
            CardService.newAction().setFunctionName("onCheckSession_"),
          ),
      ),
  );
  return b.build();
}
function errorCard_(message) {
  const b = CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader().setTitle("Error"))
    .addSection(
      CardService.newCardSection().addWidget(
        CardService.newTextParagraph().setText(
          message || "An unknown error occurred.",
        ),
      ),
    );
  return applyCommonChrome_(b).build();
}
function buildOpenEmailHintCard_() {
  const b = CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader().setTitle("Maatdesk Gmail Add-on"))
    .addSection(
      CardService.newCardSection().addWidget(
        CardService.newTextParagraph().setText(
          "Open an email to link it to a Matter.",
        ),
      ),
    );
  
  // Así es como se debe llamar a la función applyCommonChrome_
  return applyCommonChrome_(b).build();
}


/**
 * Construye la tarjeta que se muestra cuando el email YA está vinculado.
 * ¡VERSIÓN REDISEÑADA!
 * @param {Object} mailMeta - Metadatos del email actual {subject, from, to, sentAtIso, messageId}.
 * @param {Object} matter - Datos del Matter al que está vinculado {id, display}.
 */
function buildAlreadyLinkedCard_(mailMeta, matter) {
  // Construye la URL para ver el Matter en la aplicación Maatdesk
  const mdUrl = `${MD.APP}/matters/${encodeURIComponent(matter.id)}/details/`;
  // Construye la URL para ver el email específico en Gmail (usa messageId msg-f:...)
  // Asegúrate que mailMeta.messageId contiene el formato msg-f:...
  const gmailUrl = mailMeta.messageId.startsWith('msg-f:')
                 ? `https://mail.google.com/mail/u/0/#inbox/${encodeURIComponent(mailMeta.messageId)}`
                 : ""; // Si no tenemos el ID correcto, no mostramos el enlace a Gmail

  log_("buildAlreadyLinkedCard_.start", { matterId: matter.id, matterDisplay: matter.display, emailSubject: mailMeta.subject });

  const b = CardService.newCardBuilder()
    .setHeader(
      CardService.newCardHeader()
        .setTitle("✅ Email Already Linked") // Título claro
        .setSubtitle(mailMeta.subject || "(No Subject)") // Asunto como subtítulo
    );

  // --- Sección de Detalles del Email ---
  const emailSection = CardService.newCardSection()
    .addWidget(
        CardService.newKeyValue()
          .setTopLabel("From")
          .setContent(mailMeta.from || "N/A")
          .setIcon(CardService.Icon.PERSON)
     )
     .addWidget(
        CardService.newKeyValue()
          .setTopLabel("To")
          .setContent(mailMeta.to || "N/A")
          // Podríamos añadir un icono de grupo si hay varios destinatarios
     )
     .addWidget(
        CardService.newKeyValue()
          .setTopLabel("Date")
          .setContent(
              Utilities.formatDate(
                new Date(mailMeta.sentAtIso || Date.now()), // Usa fecha actual si falta
                Session.getScriptTimeZone(),
                "yyyy-MM-dd" // Formato de fecha corto
              )
           )
          .setIcon(CardService.Icon.CLOCK)
     );
    // Añadir botón para ver en Gmail si tenemos la URL correcta
    if (gmailUrl) {
        emailSection.addWidget(
            CardService.newTextButton()
              .setText("View in Gmail")
              .setOpenLink(CardService.newOpenLink().setUrl(gmailUrl))
              .setTextButtonStyle(CardService.TextButtonStyle.TEXT) // Estilo texto
        );
    }
  b.addSection(emailSection);


  // --- Sección del Matter Vinculado ---
  const matterSection = CardService.newCardSection()
    .addWidget(
      CardService.newKeyValue()
        .setTopLabel("Linked to Matter")
        .setContent(matter.display || "N/A") // Muestra el nombre/label del Matter
        .setIcon(CardService.Icon.BOOKMARK)
        // Botón principal para ver en Maatdesk
        .setButton(
          CardService.newTextButton()
            .setText("VIEW IN MAATDESK")
            .setOpenLink(CardService.newOpenLink().setUrl(mdUrl))
            // Estilo relleno para que sea la acción principal
            .setTextButtonStyle(CardService.TextButtonStyle.FILLED)
        )
    );
  b.addSection(matterSection);

  // Aplica cromo común (ej. botón Logout) y construye
  // return applyCommonChrome_(b).build(); // Descomenta si tienes applyCommonChrome_
  return b.build(); // Usa esto si no tienes applyCommonChrome_
}

// ***** REEMPLAZA TU buildPreviewCard_ CON ESTA VERSIÓN CON PERMISOS INTEGRADOS *****
function buildPreviewCard_(attachmentItems, mailMeta) {
  const chosenMatter = readChosenMatterFromCache_();
  const matterTitle = chosenMatter.label || chosenMatter.id || "Matter";
  const destinationFolder = readDestinationFolderFromCache_();

  const b = CardService.newCardBuilder().setHeader(
    CardService.newCardHeader().setTitle("Link Email"),
  );

  b.addSection(
    CardService.newCardSection()
      .addWidget(
        CardService.newKeyValue().setTopLabel("Matter").setContent(matterTitle),
      )
      .addWidget(
        CardService.newKeyValue()
          .setTopLabel("Email")
          .setContent(mailMeta.subject || ""),
      ),
  );

  // ***** 1. HACEMOS LA COMPROBACIÓN DE PERMISOS AQUÍ *****
  const hasDocPermission = apiCheckDocumentPermission_();
  log_('permission_check.result', { hasPermission: hasDocPermission });

  // ***** 2. USAMOS EL RESULTADO EN LA CONDICIÓN DEL IF *****
  if (hasDocPermission && attachmentItems && attachmentItems.length > 0) {
    // --- CASO 1: TIENE PERMISOS Y HAY ADJUNTOS ---
    // (Este es tu código original, sin cambios)
    const secAtt = CardService.newCardSection().setHeader(
      "Select attachments to upload",
    );
    attachmentItems.forEach((a) => {
      secAtt.addWidget(
        CardService.newSelectionInput()
          .setType(CardService.SelectionInputType.CHECK_BOX)
          .setFieldName(`att_${a.idx}`)
          .addItem(
            `${a.name} (${Math.round(a.size / 1024)} KB)`,
            String(a.idx),
            true,
          ),
      );
    });
    b.addSection(secAtt);

    let folderDisplayName = `🏠 ${destinationFolder.name}`;
    const MAX_PATH_LENGTH = 35;
    if (destinationFolder.path && destinationFolder.path !== "/") {
      let fullPathWithIcon = `🏠${destinationFolder.path}`;
      log_("buildPreviewCard.fullPathWithIcon", fullPathWithIcon.length);
      if (fullPathWithIcon.length > MAX_PATH_LENGTH) {
        folderDisplayName = `🏠.../${destinationFolder.name}`;
      } else {
        folderDisplayName = fullPathWithIcon;
      }
    }

    b.addSection(
      CardService.newCardSection()
        .setHeader("Destination Folder")
        .addWidget(
          CardService.newKeyValue()
            .setContent(folderDisplayName)
            .setButton(
              CardService.newTextButton()
                .setText("CHANGE")
                .setOnClickAction(
                  CardService.newAction().setFunctionName(
                    "onSelectFolderClick_",
                  ).setTextButtonStyle(CardService.TextButtonStyle.TEXT)
                ),
            ),
        ),
    );

    const btnWithAttachments = CardService.newTextButton()
      .setText("LINK EMAIL & UPLOAD FILES")
      .setOnClickAction(
        CardService.newAction().setFunctionName("onLinkAndUpload_"),
      )
      .setTextButtonStyle(CardService.TextButtonStyle.FILLED);
    b.addSection(CardService.newCardSection().addWidget(btnWithAttachments));

  } else {
    // --- CASO 2: NO TIENE PERMISOS O NO HAY ADJUNTOS ---
    
    // Mostramos el mensaje correcto según la situación
    if (attachmentItems && attachmentItems.length > 0) {
      // Si hay adjuntos pero no permisos, mostramos el aviso de permisos.
      b.addSection(
        CardService.newCardSection().addWidget(
          CardService.newTextParagraph().setText(
            "You don't have permission to upload attachments.",
          ),
        ),
      );
    } else {
      // Si simplemente no hay adjuntos, mostramos el mensaje normal.
      b.addSection(
        CardService.newCardSection().addWidget(
          CardService.newTextParagraph().setText(
            "This email has no attachments to upload.",
          ),
        ),
      );
    }
    
    // En ambos casos, el botón de acción es el simple "LINK EMAIL".
    const btnNoAttachments = CardService.newTextButton()
      .setText("LINK EMAIL")
      .setOnClickAction(
        CardService.newAction().setFunctionName("onLinkAndUpload_"),
      )
      .setTextButtonStyle(CardService.TextButtonStyle.FILLED);
    b.addSection(CardService.newCardSection().addWidget(btnNoAttachments));
  }

  return applyCommonChrome_(b).build();
}

/**
 * Construye la tarjeta de éxito con un diseño mejorado.
 * @param {string} customMessage - El mensaje principal a mostrar (HTML permitido).
 */
function buildSuccessCard_(customMessage) {
  // Leemos los datos necesarios de la caché
  const chosenMatter = readChosenMatterFromCache_();
  const mailMeta = readMetadataFromCache_(); // Necesario por si applyCommonChrome_ lo usa

  // Verificaciones básicas
  const matterLabel = chosenMatter ? (chosenMatter.label || "Selected Matter") : "Unknown Matter";
  const matterId = chosenMatter ? chosenMatter.id : null;
  const mdUrl = matterId ? `${MD.APP}/matters/${encodeURIComponent(matterId)}/details/` : MD.APP; // URL a Maatdesk

  log_("buildSuccessCard_.start", { matterLabel: matterLabel, matterId: matterId, message: customMessage });

  const b = CardService.newCardBuilder().setHeader(
    // Título claro y conciso
    CardService.newCardHeader().setTitle("✅ Success!")
  );

  // --- Sección de Resumen ---
  const summarySection = CardService.newCardSection()
    // Mensaje principal (con HTML permitido)
    .addWidget(
      CardService.newTextParagraph().setText(customMessage || "Operation completed successfully.")
    )
    // Mostramos claramente a qué Matter se vinculó
    .addWidget(
        CardService.newKeyValue()
          .setTopLabel("Linked to Matter")
          .setContent(matterLabel)
          .setIcon(CardService.Icon.BOOKMARK)
          // Podríamos añadir un botón aquí también si quisiéramos
          // .setButton(CardService.newTextButton().setText("View").setOpenLink(CardService.newOpenLink().setUrl(mdUrl)))
    );
  b.addSection(summarySection);

  // --- Sección de Acciones ---
  const actionsSection = CardService.newCardSection()
    .addWidget(
      CardService.newButtonSet()
        // Botón para ir a Maatdesk
        .addButton(
          CardService.newTextButton()
            .setText("View in Maatdesk")
            .setOpenLink(CardService.newOpenLink().setUrl(mdUrl))
            // Estilo TEXT para diferenciarlo del botón principal
            .setTextButtonStyle(CardService.TextButtonStyle.TEXT)
            // Deshabilitar si no pudimos obtener el ID del Matter
            .setDisabled(!matterId)
        )
        // Botón para continuar/refrescar el Add-on
        .addButton(
          CardService.newTextButton()
            .setText("Continue") // O podríamos llamarlo "Refresh Add-on"
            .setOnClickAction(
              // Llama a la función que fuerza la recarga
              CardService.newAction().setFunctionName("onCheckSession_")
            )
            // Estilo FILLED para que sea la acción principal
            .setTextButtonStyle(CardService.TextButtonStyle.FILLED)
        )
    );
  b.addSection(actionsSection);

  return b.build(); // Devolvemos la tarjeta construida
}

/* ========= 7) Helpers de Caché, Gmail, API, Payloads ========= */
function saveMetadataToCache_(mailMeta) {
  try {
    const key = "current_mail_meta";
    CacheService.getUserCache().put(key, JSON.stringify(mailMeta), 1800);
    log_("cache.metadata_saved", mailMeta);
  } catch (e) {
    log_("cache.save_error", { error: String(e) });
  }
}
function readMetadataFromCache_() {
  try {
    const key = "current_mail_meta";
    const raw = CacheService.getUserCache().get(key);
    return raw ? JSON.parse(raw) : {};
  } catch (e) {
    log_("cache.read_error", { error: String(e) });
    return {};
  }
}
function saveChosenMatterToCache_(chosenMatter) {
  try {
    const key = "current_matter_meta";
    CacheService.getUserCache().put(key, JSON.stringify(chosenMatter), 1800);
    log_("cache.matter_saved", chosenMatter);
  } catch (e) {
    log_("cache.matter_save_error", { error: String(e) });
  }
}
function readChosenMatterFromCache_() {
  try {
    const key = "current_matter_meta";
    const raw = CacheService.getUserCache().get(key);
    return raw ? JSON.parse(raw) : {};
  } catch (e) {
    log_("cache.matter_read_error", { error: String(e) });
    return {};
  }
}
function ensureGmailToken_(e) {
  const tok = e?.messageMetadata?.accessToken || e?.gmail?.accessToken;
  if (!tok) throw new Error("Gmail accessToken not present in the event.");
  GmailApp.setCurrentMessageAccessToken(tok);
}
function getCurrentMessageAndAttachments_(e) {
  const messageId =
    e?.gmail?.messageId ||
    e?.messageMetadata?.messageId ||
    readMetadataFromCache_().messageId;
  if (!messageId) throw new Error("No messageId present in event or cache.");
  ensureGmailToken_(e);
  const msg = GmailApp.getMessageById(messageId);
  const blobs =
    msg.getAttachments({
      includeInlineImages: true,
      includeAttachments: true,
    }) || [];
  const items = blobs.map((b, i) => ({
    idx: i,
    name: b.getName() || "Attachment " + (i + 1),
    size: b.getBytes().length,
  }));
  return { msg, items };
}
function fetchWithBackoff_(url, opts, tries = 2) {
  let delay = 300,
    last = null;
  for (let i = 0; i < tries; i++) {
    const resp = UrlFetchApp.fetch(url, { muteHttpExceptions: true, ...opts });
    if (![429, 503].includes(resp.getResponseCode())) return resp;
    last = resp;
    Utilities.sleep(delay);
    delay *= 2;
  }
  return last;
}

/**
 * Realiza una petición GET a la API REST de Gmail.
 * AHORA OBTIENE SU PROPIO TOKEN DE ACCESO.
 * @param {string} path - El path de la API a consultar (ej. /threads/thread123).
 * @return {Object} El objeto JSON de la respuesta.
 */
function gmailApiGet_(path) {
  const GMAIL_API_BASE = "https://gmail.googleapis.com/gmail/v1/users/me";
  const url = `${GMAIL_API_BASE}${path}`;
  let gmailToken = "";

  try {
    // ¡¡CAMBIO CLAVE!! Obtenemos el token directamente de Apps Script.
    gmailToken = ScriptApp.getOAuthToken();
    
    if (!gmailToken) {
      log_("gmailApiGet_.error", "ScriptApp.getOAuthToken() returned null.");
      throw new Error("Could not get OAuth token from ScriptApp.");
    }

    const options = {
      method: "get",
      headers: {
        "Authorization": `Bearer ${gmailToken}`
      },
      contentType: "application/json",
      muteHttpExceptions: true
    };

    const resp = UrlFetchApp.fetch(url, options);
    const code = resp.getResponseCode();
    const respText = resp.getContentText();

    if (code >= 200 && code < 300) {
      log_("gmailApiGet_.success", { path: path, status: code });
      return JSON.parse(respText || "{}");
    } else if (code === 401 || code === 403) {
      log_("gmailApiGet_.auth_error", { path: path, status: code, token_used: "ScriptApp" });
      // Si falla con 401/403 usando este token, el permiso FALTA en el manifiesto.
      throw new Error(`Gmail API permission error (Status ${code}).`);
    } else {
      log_("gmailApiGet_.api_error", { path: path, status: code, response: respText });
      throw new Error(`Gmail API error (Status ${code}): ${respText}`);
    }
  } catch (e) {
    log_("gmailApiGet_.fatal", { error: String(e), path: path });
    throw e; // Relanza el error para que la función que llama lo maneje
  }
}

/**
 * Función de ayuda para extraer un valor de header específico.
 * @param {Array<Object>} headers - El array de headers de la API de Gmail.
 * @param {string} name - El nombre del header a buscar (ej. 'Subject').
 * @return {string} El valor del header o "".
 */
function getHeaderValue_(headers, name) {
  try {
    const header = headers.find(h => h.name.toLowerCase() === name.toLowerCase());
    return header ? header.value : "";
  } catch (e) {
    return ""; // Devuelve vacío si hay algún error
  }
}

/**
 * Obtiene y procesa todos los mensajes de un hilo.
 * ¡VERSIÓN FINAL v6! Guarda el Message-ID del header como messageId.
 */
function getThreadDetails_(threadId) { // threadId es hex (formato numérico/hexadecimal)
  const path = `/threads/${encodeURIComponent(threadId)}?format=full`;
  log_("getThreadDetails_.start", { threadId: threadId, format: "full" });
  let jsonResponse;
  try {
      jsonResponse = gmailApiGet_(path); // Llama a la API de Gmail
  } catch (apiErr) {
      log_("getThreadDetails_.gmailApiGet_FAILED", { error: String(apiErr) });
      return []; // Devuelve vacío si la API falla
  }

  // Verifica si la respuesta es válida
  if (!jsonResponse || !Array.isArray(jsonResponse.messages)) {
    log_("getThreadDetails_.no_messages_found_or_invalid_response", { threadId: threadId, response: jsonResponse });
    return []; // Devuelve array vacío si no hay mensajes
  }
  log_("getThreadDetails_.raw_api_response_messages_count", { count: jsonResponse.messages.length });

  // Mapea cada mensaje de la respuesta de la API
  const messages = jsonResponse.messages.map((msg, index) => {
    log_(`getThreadDetails_.map_START_msg_${index}`, { msg_id_from_api: msg ? msg.id : 'null'});

    // Comprobación de seguridad por si falta el payload
    if (!msg || !msg.payload) {
      log_(`getThreadDetails_.skip_message_${index}`, { msgId: (msg ? msg.id : 'unknown'), reason: "Message has no payload" });
      return null; // Marcar para filtrar después
    }

    const headers = msg.payload.headers || []; // Obtiene los encabezados
    const messageIdHex = msg.id; // ID hexadecimal de la API de Gmail
    log_(`getThreadDetails_.PROCESSING_MSG_${index}`, { messageIdHexFromApi: messageIdHex });

    // --- Función interna para buscar adjuntos ---
    const findAttachments = (parts) => {
      let attachments = [];
      if (!parts) return attachments;
      parts.forEach(part => {
        if (part.filename && part.body && part.body.attachmentId) {
          attachments.push({ attachmentId: part.body.attachmentId, filename: part.filename, contentType: part.mimeType || "application/octet-stream", size: part.body.size || 0 });
        }
        if (part.parts) { attachments = attachments.concat(findAttachments(part.parts)); }
      });
      return attachments;
    };
    const attachments = findAttachments(msg.payload.parts);
    log_(`getThreadDetails_.found_attachments_${index}`, { count: attachments.length });

    // --- OBTENCIÓN DEL Message-ID DEL HEADER ---
    let headerMessageId = ""; // Variable para guardar el ID del header
    try {
        const messageIdHeader = getHeaderValue_(headers, 'Message-ID'); // Usa nuestra función helper
        if (messageIdHeader) {
            // Limpiamos los < > que a veces lo rodean y espacios
            headerMessageId = messageIdHeader.replace(/^</, '').replace(/>$/, '').trim();
            log_(`getThreadDetails_.id_from_header_${index}`, { hex: messageIdHex, header_message_id: headerMessageId });
        } else {
             // Si el header falta, usamos el ID Hex como fallback MUY improbable
             log_(`getThreadDetails_.header_missing_using_hex_fallback_${index}`, { hex: messageIdHex });
             headerMessageId = messageIdHex;
        }
        // Verificación final: si está vacío después de limpiar, usamos hex
        if (!headerMessageId) {
            log_(`getThreadDetails_.WARNING_empty_header_using_hex_fallback_${index}`, { hex: messageIdHex });
            headerMessageId = messageIdHex;
        }
    } catch(idErr){
        // Si hay una EXCEPCIÓN durante la obtención del header
        log_(`getThreadDetails_.id_extraction_ERROR_exception_${index}`, {hexId: messageIdHex, error: String(idErr), stack: idErr.stack});
        headerMessageId = messageIdHex; // Fallback final al hex
    }
    // --- Fin Obtención de ID ---

    // Devolvemos el objeto mensaje limpio, usando el ID del header como messageId principal
    const messageData = {
      messageId: headerMessageId, // ¡¡El ID del header (o fallback hex)!!
      threadId: msg.threadId,     // Hexadecimal
      date: new Date(parseInt(msg.internalDate, 10)).toISOString(),
      from: getHeaderValue_(headers, 'From'),
      subject: getHeaderValue_(headers, 'Subject'),
      attachments: attachments
    };
    log_(`getThreadDetails_.message_data_RESULT_${index}`, { messageId: messageData.messageId, threadId: messageData.threadId });
    return messageData;
  })
  .filter(Boolean); // Elimina los mensajes nulos

  log_("getThreadDetails_.success", { threadId: threadId, finalMessageCount: messages.length });
  return messages; // Devuelve el array de mensajes procesados
}

/**
 * Lee los detalles del hilo desde la caché.
 * @return {Array<Object>} El array de objetos de mensaje, o un array vacío.
 */
function readThreadDetailsFromCache_() {
  try {
    const key = "current_thread_details";
    const raw = CacheService.getUserCache().get(key);
    return raw ? JSON.parse(raw) : [];
  } catch (e) {
    log_("cache.thread_details_read_error", { error: String(e) });
    return [];
  }
}

function callMaatdesk_(path, opts, atOverride) {
  // Llama directamente a getAccessTokenLax_
  let at = atOverride || getAccessTokenLax_(); // Puede lanzar SESSION_EXPIRED
  if (!at) throw new Error("SESSION_EXPIRED"); // Si getAccessTokenLax_ falló (o devolvió null), lanzamos error

  const headers = {
    Authorization: `Bearer ${at}`,
    Accept: "application/json",
    "X-Google-User": Session.getActiveUser().getEmail(),
    ...opts?.headers,
  };
  let resp = fetchWithBackoff_(`${MD.API}${path}`, {
    headers,
    muteHttpExceptions: true,
    ...opts,
  });

  // La lógica de reintento con refreshToken_ sigue igual
  if ([401, 403].includes(resp.getResponseCode())) {
    log_("callMaatdesk_.attempting_refresh", { path: path, status: resp.getResponseCode() });
    const newAt = refreshToken_(); // refreshToken_ puede devolver null si falla
    if (newAt) {
      at = newAt;
      headers.Authorization = `Bearer ${at}`;
      log_("callMaatdesk_.retrying_with_new_token", { path: path });
      resp = fetchWithBackoff_(`${MD.API}${path}`, {
        headers,
        muteHttpExceptions: true,
        ...opts,
      });
    } else {
      // Si refreshToken_ devolvió null, lanzamos SESSION_EXPIRED
      log_("callMaatdesk_.refresh_failed", { path: path });
      throw new Error("SESSION_EXPIRED");
    }
  }
  return resp;
}
function mdGetJson_(url) {
  const resp = callMaatdesk_(url, { method: "get" });
  const code = resp.getResponseCode();
  if (code < 200 || code >= 300) throw new Error(`API Error: HTTP ${code}`);
  return JSON.parse(resp.getContentText() || "{}");
}
function apiByEmail_(gmailIdentifier) {
  const url = `/api/v2/Matters/select-options/by-email?emailId=${encodeURIComponent(gmailIdentifier)}`;
  try {
    const jsonResponse = mdGetJson_(url);
    log_("api.byEmail.raw_response", {
      identifier_sent: gmailIdentifier,
      response_body: jsonResponse,
    });
    const data = Array.isArray(jsonResponse?.data)
      ? jsonResponse.data
      : Array.isArray(jsonResponse)
        ? jsonResponse
        : [];
    return data
      .map((x) => ({ id: x.id || x.matterId, label: x.label || x.displayName }))
      .filter((x) => x.id && x.label);
  } catch (e) {
    log_("api.byEmail.error", String(e));
    if (String(e.message).includes("SESSION_EXPIRED")) {
      throw e;
    }
    log_("api.byEmail.error", e);
    return [];
  }
}
function apiByFromTo_(address) {
  const url = `/api/v2/Matters/select-options/by-from-to?address=${encodeURIComponent(address)}`;
  try {
    const json = mdGetJson_(url);
    const data = Array.isArray(json?.data)
      ? json.data
      : Array.isArray(json)
        ? json
        : [];
    return data
      .map((x) => ({ id: x.id || x.matterId, label: x.label || x.displayName }))
      .filter((x) => x.id && x.label);
  } catch (e) {
    log_("api.byFromTo.error", String(e));
    if (String(e.message).includes("SESSION_EXPIRED")) {
      throw e;
    }
    return [];    
  }
}
function apiByLabel_(label, limit = 8) {
  const url = `/api/v2/Matters/select-options?labelFilter=${encodeURIComponent(label)}`;
  try {
    const json = mdGetJson_(url);
    const data = Array.isArray(json?.data)
      ? json.data
      : Array.isArray(json)
        ? json
        : [];
    return data
      .map((x) => ({ id: x.id || x.matterId, label: x.label || x.displayName }))
      .filter((x) => x.id && x.label)
      .slice(0, limit);
  } catch (e) {
    log_("api.byLabel.error", String(e));
    return [];
  }
}

/**
 * Llama a la API para comprobar si el usuario tiene permisos de documentos.
 * ¡VERSIÓN CORREGIDA! Usa lógica bitwise para chequear
 * el permiso 'Create' (valor 2).
 */
function apiCheckDocumentPermission_() {
  const url = `/api/Account/permission`; 
  
  try {
    const jsonResponse = mdGetJson_(url);
    log_('permission_check.api_response', { response: jsonResponse });

    // Este es el valor de 'Create' de tu enum
    const CREATE_PERMISSION_FLAG = 2; 

    const userPermissionValue = (jsonResponse?.data?.documentPermission || 0);

    const hasPermission = (userPermissionValue & CREATE_PERMISSION_FLAG) === CREATE_PERMISSION_FLAG;
    
    log_('permission_check.bitwise_check', { 
      userValue: userPermissionValue,
      flag: CREATE_PERMISSION_FLAG,
      hasPermission: hasPermission
    });

    return hasPermission;
    
  } catch (e) {
    log_('permission_check.error', String(e));
    return false; // En caso de error, por seguridad, denegamos el permiso.
  } 
}

/**
 * Llama al endpoint para obtener los emails ya vinculados para un hilo.
 * ¡VERSIÓN CORREGIDA! Devuelve un array de objetos { gmailId, matterId }.
 * @param {string} threadId - El ID del hilo a consultar (hex).
 * @return {Array<Object>} Lista de objetos con info de vinculación.
 */
function apiGetLinkedMessages_(threadId) {
  const url = `/api/matters/gmail-emails/thread/${encodeURIComponent(threadId)}`;
  log_('apiGetLinkedMessages_.requesting', { url: url });
  try {
    const jsonResponse = mdGetJson_(url); // mdGetJson_ maneja errores básicos
    log_('apiGetLinkedMessages_.raw_response', { response: jsonResponse });

    // Esperamos un array de objetos como [{ id, matterId, gmailId, ... }]
    if (Array.isArray(jsonResponse)) {
      // Mapeamos a la estructura que necesitamos { gmailId, matterId }
      const linkedData = jsonResponse.map(item => ({
          gmailId: item.gmailId, // El msg-f:... o header ID (según lo que guarde la API)
          matterId: item.matterId // El ID del Matter
      })).filter(item => item.gmailId && item.matterId); // Filtra items inválidos

      log_('apiGetLinkedMessages_.extracted_data', { threadId: threadId, count: linkedData.length, data: linkedData });
      return linkedData; // Devuelve el array de objetos { gmailId, matterId }
    }
    // Si la respuesta no es un array
    log_('apiGetLinkedMessages_.unexpected_response_type', { threadId: threadId, type: typeof jsonResponse });
    return []; // Devuelve array vacío
  } catch (e) {
    log_("apiGetLinkedMessages_.error", { threadId: threadId, error: String(e) });
    // Si el error es de sesión, lo re-lanzamos
    if (String(e.message).includes("SESSION_EXPIRED")) {
      throw e;
    }    
    log_("apiGetLinkedMessages.error", e);
    //return [];
    throw e
  }
}

function getCheckboxFlag_(formInputs, field) {
  const v = formInputs?.[field]?.stringInputs?.value;
  return Array.isArray(v) && v.includes("1");
}
function getSelectedAttachmentIndexes_(formInputs, total) {
  const selected = [];
  for (let i = 0; i < total; i++) {
    const v = formInputs?.[`att_${i}`]?.stringInputs?.value;
    if (Array.isArray(v) && v.includes(String(i))) selected.push(i);
  }
  return selected;
}

/**
 * Construye el payload de un solo correo para la API.
 * ¡VERSIÓN MODIFICADA! Añade un sufijo único a los .eml para evitar colisiones.
 */
function buildGmailPayload_(msg, attItems, opts, mailMeta) {
  const { includeAttachments, selectedIndexes, includeEml } = opts ||
    {};
  const cidMap = extractCidMapFromRaw_(msg.getRawContent() || "");

  const idToSend = mailMeta.messageId; 
  const threadIdToSend = mailMeta.threadId;

  log_('buildGmailPayload.id_check', {
      id_being_sent_as_gmailId: idToSend, 
      id_being_sent_as_threadId: threadIdToSend 
  });
  
  const item = {
    gmailId: idToSend, 
    threadId: threadIdToSend, 
    subject: msg.getSubject(),
    from: msg.getFrom(),
    to: msg.getTo() ||
      "",
    body: INCLUDE_BODY_HTML ? msg.getBody() || "" : "",
    sentAtUtc: (msg.getDate() || new Date()).toISOString(),
    attachments: [],
  };
  
  log_('buildGmailPayload.payload', {
      item
  });

  // (Lógica de adjuntos normales - sin cambios)
  if (includeAttachments && selectedIndexes?.length) {
    const blobs = msg.getAttachments({
      includeInlineImages: true,
      includeAttachments: true,
    });
    selectedIndexes.forEach((idx) => {
      const b = blobs[idx];
      if (!b) return;
      const name = b.getName() || `attachment-${idx + 1}`;
      const bytes = b.getBytes();
      item.attachments.push({
        fileName: name,
        contentType: b.getContentType() || "application/octet-stream",
        contentBase64: Utilities.base64Encode(bytes),
        size: bytes.length,
        contentId: cidMap[name] || "",
        inline: !!cidMap[name],
      });
    });
  }

  if (includeEml) {
    try {
      const raw = msg.getRawContent();
      const bytes = Utilities.newBlob(raw, "message/rfc822").getBytes();
      
      //Generamos un sufijo aleatorio de 6 caracteres
      const uniqueSuffix = randomStr_(6); 
      
      item.attachments.push({
        // ¡MODIFICADO! Añadimos el sufijo antes de la extensión .eml
        fileName: sanitizeFileName_(msg.getSubject() || "email") + `_${uniqueSuffix}.eml`,
        contentType: "message/rfc822",
        contentBase64: Utilities.base64Encode(bytes),
        size: bytes.length,
      });
    } catch (e) {
      log_("buildGmailPayload.eml.error", String(e));
    }
  }
  
  return item;
}

/**
 * Extrae un mapa de Content-IDs a nombres de archivo desde el raw email.
 * @param {string} raw - El contenido raw del email.
 * @return {Object} Un mapa ej. {"logo.png": "ii_12345"}
 */
function extractCidMapFromRaw_(raw) {
  const map = {};
  try {
    const re = /Content-ID:\s*<([^>]+)>[\s\S]*?filename="?([^";\n]+)"?/gi;
    let m;
    while ((m = re.exec(raw))) {
      map[m[2]] = m[1];
    }
  } catch (e) {
    log_("extractCidMap.error", String(e));
  }
  return map;
}

/**
 * Limpia un nombre de archivo para que sea válido.
 * @param {string} name - El nombre del archivo (ej. el subject).
 * @return {string} Un nombre de archivo seguro.
 */
function sanitizeFileName_(name) {
  return (
    (name || "email")
      .replace(/[\\/:*?"<>|]+/g, " ")
      .trim()
      .slice(0, 120) || "email"
  );
}

/* ========= 8) Limpieza y Desconexión ========= */
function wipeLocalState_() {
  try {
    const up = userProps_();
    // Borramos todas las propiedades definidas en PROPS
    Object.keys(PROPS).forEach((key) => {
      try {
        // Aseguramos que solo borramos las claves definidas en nuestro objeto PROPS
        if (PROPS[key]) {
           up.deleteProperty(PROPS[key]);
        }
      } catch (_) {}
    });
    // ¡Se eliminó la línea CacheService.getUserCache().remove("MD_AT_PIN");!
    log_("wipe.success", {});
  } catch (e) {
    log_("wipeLocalState_.error", String(e));
  }
}

function setForcePromptLogin_() {
  userProps_().setProperty(PROPS.FORCE_PROMPT_LOGIN, "1");
}
function consumeForcePromptLogin_() {
  const up = userProps_();
  const v = up.getProperty(PROPS.FORCE_PROMPT_LOGIN) === "1";
  if (v) up.deleteProperty(PROPS.FORCE_PROMPT_LOGIN);
  return v;
}

function buildToast_(msg) {
  log_("buildToast_.error",msg);
  return CardService.newActionResponseBuilder()
    .setNotification(CardService.newNotification().setText(msg))
    .build();
}

/**
 * FUNCIÓN DE DEPURACIÓN
 * Borra manualmente los tokens de acceso y de refresco para simular una sesión expirada.
 */
function forceExpireSession() {
  const up = userProps_();
  up.deleteProperty(PROPS.ACCESS_TOKEN);
  up.deleteProperty(PROPS.REFRESH_TOKEN);
  up.deleteProperty(PROPS.PINNED_TOKEN);
  CacheService.getUserCache().remove("MD_AT_PIN");
  // Opcional: para ver en los logs que se ejecutó
 // console.log("[DEBUG] Session tokens have been manually deleted.");
}

/**
 * Decodifica la parte del payload de un JSON Web Token (JWT).
 * @param {string} token El JWT a decodificar.
 * @return {Object} El payload del token como un objeto.
 */
function parseJwt_(token) {
  try {
    const base64Url = token.split('.')[1];
    const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
    const jsonPayload = Utilities.newBlob(Utilities.base64Decode(base64)).getDataAsString();
    log_('jwt.parse', jsonPayload);
    return JSON.parse(jsonPayload);
  } catch (e) {
    log_('jwt.parse_error', { error: String(e) });
    return {};
  }
}
