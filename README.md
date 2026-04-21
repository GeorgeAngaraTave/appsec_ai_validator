# AI AppSec Validator

CLI para validación estática asistida de hallazgos SAST en proyectos Python. El objetivo es confirmar o rechazar hallazgos de **SQL Injection**, **SSRF** y **Command Injection** con trazabilidad **source → sink**, explicación técnica, sanitizers detectados, supuestos y priorización.

## Qué hace

- Lee un proyecto Python y un archivo `findings.json`
- Analiza el código usando `ast`
- Reconstruye una ruta básica source → sink
- Clasifica hallazgos como `True Positive` o `False Positive`
- Genera `report.json` y `report.html`
- Incluye casos sample y pruebas

## Enfoque

La solución no reemplaza el SAST. Toma hallazgos previos y los valida combinando:

1. **Análisis estático estructural** con AST
2. **Heurísticas de AppSec** por tipo de vulnerabilidad
3. **Explicación asistida** basada en evidencia del código

Para esta entrega, el “agente” está implementado como un validador determinístico con reglas OWASP-friendly, de forma que el proyecto funcione localmente sin depender de API externa. La arquitectura deja listo el punto de extensión para conectar un LLM real si lo deseas.

## Estructura

```bash
app/
  cli.py
  main.py
  parsers/
  analyzers/
  agents/
  models/
  services/
  utils/
sample/
reports/
tests/
```

## Instalación

```bash
python -m venv .venv
source .venv/bin/activate  # Linux/macOS
# .venv\Scripts\activate   # Windows
pip install -r requirements.txt
```

## Ejecución rápida

```bash
python -m app.main validate --project sample --findings sample/findings.json --output reports
```

O usando el script:

```bash
appsec-validate validate --project sample --findings sample/findings.json --output reports
```

## Salida esperada

- `reports/report.json`
- `reports/report.html`

## Ejemplo de resultado sobre el sample

- `vuln_01` SQL Injection en `login` → **True Positive**
- `vuln_02` SQL Injection en `new_login` → **False Positive** (query parametrizada)
- `vuln_03` SSRF en `check_username` → **False Positive** (host fijo, usuario controla solo path)
- `vuln_04` Command Injection en `is_online_username` → **True Positive**

## Arquitectura resumida

### 1. Ingesta
Lee el repo Python y el archivo de hallazgos.

### 2. Parser AST
Extrae funciones, llamadas, variables, asignaciones, f-strings y líneas relevantes.

### 3. Motor source-to-sink
Relaciona entradas controladas por usuario con sinks peligrosos y construye una traza explicable.

### 4. Validador AppSec
Aplica reglas por vulnerabilidad:

- **SQL Injection**: detecta concatenación, f-string, `%` formatting, `.format`, queries parametrizadas
- **SSRF**: diferencia host controlado vs host fijo con path variable
- **Command Injection**: detecta `os.system`, `subprocess.*`, shell strings con entrada de usuario

### 5. Reportería
Consolida veredicto, explicación, severidad, supuestos, sanitizers y contraejemplos.

## Lista de herramientas, MCP tools y modelo utilizados

### Herramientas de desarrollo

| Herramienta | Versión | Uso |
|---|---|---|
| Python | 3.11+ | Lenguaje base |
| `ast` | stdlib | Análisis estático de código fuente |
| `Typer` | ≥0.12 | Interfaz CLI |
| `Pydantic` | ≥2.6 | Modelos y validación de datos |
| `Jinja2` | ≥3.1 | Generación de reporte HTML |
| `pytest` | ≥8.0 | Pruebas unitarias |

### Modelo / Agente

La implementación actual usa **reglas determinísticas locales** (sin API externa), lo que permite ejecutar el validador sin credenciales ni latencia de red. El punto de extensión está en `app/agents/validator_agent.py`: reemplazar el método `validate()` con una llamada a un LLM es el único cambio necesario.

El modelo objetivo para la extensión LLM es **Claude 3.5 Sonnet** (`claude-sonnet-4-6`) vía Anthropic API, por su capacidad de razonamiento sobre código y conocimiento de OWASP.

### MCP Tools (Model Context Protocol)

La arquitectura está preparada para integrarse con servidores MCP que expongan contexto adicional al agente. Las integraciones planificadas son:

| MCP Tool | Propósito |
|---|---|
| `mcp__filesystem` | Leer archivos del proyecto analizado sin pasar rutas absolutas al prompt |
| `mcp__code_search` | Búsqueda semántica en el codebase para trazabilidad interprocedural profunda |
| `mcp__bandit` / `mcp__semgrep` | Consumir hallazgos directamente desde herramientas SAST reales como fuente de entrada |
| `mcp__nvd` | Consultar CVEs relacionados con el patrón de vulnerabilidad detectado para enriquecer la explicación |

En la versión actual estas capacidades están implementadas localmente con `ast` y heurísticas. Cuando se conecte el LLM, los MCP tools reemplazarán esas implementaciones con llamadas al servidor correspondiente, manteniendo la misma interfaz (`TraceEvidence` → `AnalysisResult`).

## Cómo lo explicaría en entrevista

> Diseñé un validador asistido por IA para reducir falsos positivos de SAST, no un scanner desde cero. Mi enfoque fue primero extraer evidencia estática del código con AST y después aplicar razonamiento de seguridad sobre esa evidencia. Así el sistema explica por qué un hallazgo es explotable o no, con source-to-sink, sanitizers, supuestos y contraejemplo mínimo.

## Ejecutar pruebas

```bash
pytest -q
```

## Extensión futura

- Integrar un LLM real en `app/agents/validator_agent.py`
- Mejorar trazabilidad interprocedural compleja
- Soportar más sinks y frameworks web
- Consumir reportes SAST reales de Bandit, Semgrep o CodeQL
