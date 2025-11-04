# Maatdesk Gmail Addon

## Descripción
Add-on de Gmail desarrollado con Google Apps Script para vincular correos de Gmail a matters en Maatdesk.

## Estructura del Proyecto
```
maatdesk-gmail-addon/
├── src/
│   ├── Code.js              # Código principal del addon
│   ├── FoldersForMatter.js  # [Descripción del archivo]
│   └── appsscript.json      # Configuración de Apps Script
├── .clasp-dev.json          # Configuración de clasp para desarrollo
├── .clasp-prod.json         # Configuración de clasp para producción
├── prepare.sh               # Script para preparar archivos según ambiente
├── package.json             # Dependencias del proyecto
└── README.md               # Este archivo
```

## Configuración del Entorno

### Prerequisitos
- Node.js instalado
- Google Apps Script CLI (clasp) instalado: `npm install -g @google/clasp`
- Cuenta de Google con acceso a Google Apps Script

### Configuración Inicial
1. Instalar dependencias:
   ```bash
   npm install
   ```

2. Configurar clasp para desarrollo o producción:
   ```bash
   # Para desarrollo
   ./prepare.sh dev
   
   # Para producción
   ./prepare.sh prod
   ```

## Deployment

### Configuración de Autenticación
Para el deployment automatizado, es necesario configurar la autenticación de clasp:

1. **Generar archivo de credenciales encriptado** (requiere máquina Linux):
   ```bash
   # Primero, hacer login en clasp
   clasp login
   
   # Encriptar el archivo de credenciales usando GPG
   gpg -o .clasprc.json.gpg --symmetric --cipher-algo AES256 ~/.clasprc.json
   ```

2. **Configurar GitHub Secrets**:
   - Cuando GPG solicite una contraseña, guárdala como un secret en GitHub
   - Ve a Settings > Secrets and variables > Actions
   - Crear un nuevo secret con el nombre `GPG_PASSPHRASE` y la contraseña como valor

3. **Subir archivo encriptado**:
   - Agregar el archivo `.clasprc.json.gpg` al repositorio
   - El archivo encriptado es seguro para incluir en el control de versiones

### Proceso de Deployment
El deployment se realiza automáticamente a través de GitHub Actions cuando se hace push a las ramas configuradas.

## Scripts Disponibles

| Script | Descripción |
|--------|-------------|
| `./prepare.sh dev` | Configura el entorno para desarrollo |
| `./prepare.sh prod` | Configura el entorno para producción |

## Archivos de Configuración

- **`.clasp-dev.json`**: Configuración de clasp para el entorno de desarrollo
- **`.clasp-prod.json`**: Configuración de clasp para el entorno de producción
- **`.clasp.json`**: Archivo activo generado por `prepare.sh` (no versionar)

## Seguridad
- Los archivos `.clasp.json`, `.clasprc.json` y similares están incluidos en `.gitignore`
- Las credenciales se almacenan encriptadas usando GPG con cifrado AES256
- Las contraseñas se gestionan como secrets de GitHub

## Contribución
1. Hacer fork del repositorio
2. Crear una nueva rama para la feature: `git checkout -b feature/nueva-funcionalidad`
3. Hacer commit de los cambios: `git commit -am 'Agregar nueva funcionalidad'`
4. Push a la rama: `git push origin feature/nueva-funcionalidad`
5. Crear un Pull Request

## Licencia
[Especificar la licencia del proyecto]


