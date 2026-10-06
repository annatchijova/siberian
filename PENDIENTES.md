# Pendientes de SIBERIAN

Actualizado: 2026-10-05

Este archivo separa el trabajo que podemos avanzar en este entorno de la validación que depende de una VM Windows. Los elementos marcados `bloqueado por entorno` siguen pendientes; no cuentan como evidencia ni como nivel terminado.

## Nivel 1 — Matriz contextual y validación

### Podemos avanzar ahora

- [ ] Revisar la semántica y límites de cada expectativa contra documentación primaria; actualizar `docs/CATALOG_MATRIX.md` sin extrapolar más allá de la fuente.
- [x] Definir un formato de registro de corrida versionado que vincule configuración exacta, acciones, adquisiciones, versiones de parser, hashes y errores (`lab/run-record.template.json`).
- [x] Revisar estáticamente límites, permisos, consultas documentadas y escritura del recolector PowerShell; el runtime sigue pendiente de Windows.
- [x] Revisar que la API preserve `PRESENT`, `CONFIRMED_ABSENT`, `UNKNOWN` y `OUT_OF_SCOPE`, sus causas y referencias, y que el digest cubra los campos declarados.

### Bloqueado por entorno — requiere Windows

- [ ] Ejecutar `lab/collect_windows_baseline.ps1` en una VM desechable y corregir incompatibilidades con Windows PowerShell 5.1 y la versión de Windows elegida.
- [ ] Ejecutar controles positivos de generación de 4688, 5156, 4624, 4634 y USN; preservar adquisiciones crudas e intervenciones con hashes.
- [ ] Ejecutar controles negativos con auditoría deshabilitada o condición no aplicable; demostrar que el recolector registra fallos y no los convierte en cero.
- [ ] Medir al menos un mecanismo de pérdida benigno por fuente (retención/rollover para Security y avance/wrap para USN) con snapshots recuperables.
- [ ] Revisar las corridas de forma independiente y completar filas de aplicabilidad solo para las imágenes/configuraciones realmente medidas.

**Estado:** no hay VM Windows disponible en este entorno. No se ejecutaron corridas, no hay resultados empíricos y el script PowerShell aún no tiene validación de sintaxis/ejecución en Windows. El Nivel 1 permanece abierto.

## Siguiente secuencia

La primera entrega corta se define en [`docs/PRODUCT_SCOPE.md`](docs/PRODUCT_SCOPE.md). Desde este entorno, continuar con:

1. [x] Definir el esquema JSON de caso y política estricta de validación (`docs/CASE_FILE_FORMAT.md`).
2. [x] Implementar el flujo local `validate` / `analyze` / `explain` sobre la biblioteca.
3. [x] Añadir un caso sintético de brecha de adquisición y cobertura automatizada de entradas hostiles.
4. [x] Añadir un caso sintético con los cuatro estados y una ausencia condicionada; los fixtures no son validación Windows.
5. Mantener las etiquetas de laboratorio en `not-tested` hasta revisar evidencia reproducible.
6. Cuando exista acceso a una VM Windows, realizar el preflight del recolector antes de experimentos y comenzar con controles positivos/negativos no destructivos.

No calibrar scores ni inferir borrado selectivo sin corridas controladas y evaluación ciega conforme a `docs/LEVEL1_VALIDATION_PROTOCOL.md`.

## Niveles posteriores

- [x] Nivel 2: lectura de casos y `validate` / `analyze` / `explain` desde la CLI.
- [x] Nivel 3: hipótesis rivales, dependencias de artefactos y contrafácticos explícitos (`rivals`). Auditoría en [`docs/red-team/NIVEL3_AUDIT.md`](docs/red-team/NIVEL3_AUDIT.md).
- [ ] Nivel 4: evaluación empírica ciega y calibración, solo si los datos discriminan las hipótesis. **Bloqueado**: requiere Windows.
- [x] Nivel 5: bundle sellado y verificador independiente (`seal` / `verify`, stdlib-only).
- [x] Nivel 6 — Plaso: importador a case file. Decisión documentada en [`docs/PLASO_IMPORT.md`](docs/PLASO_IMPORT.md): solo presencias con mapeo explícito; una fila ausente no prueba ausencia.
- [x] Nivel 6 — provenance: todo adaptador registra digest de origen, nombre y versión del parser, transformaciones ordenadas y limitaciones declaradas.
- [x] Nivel 6 — `batch`: un adaptador sobre muchos artefactos, un output por input; se niega a mezclar fuentes o casos y revela todo límite que truncó la corrida.
- [x] Nivel 6 — sellado y verificación independiente: todo export lleva `provenance_hash` / `payload_hash` / `export_hash`, y [`forensics/verify_siberian.py`](forensics/verify_siberian.py) los re-deriva sin importar SIBERIAN. Ver [`docs/EXPORT_VERIFICATION.md`](docs/EXPORT_VERIFICATION.md).

## Estado de los adaptadores de artefacto — leer antes de usar

Cinco adaptadores están implementados (`import-mft`, `import-prefetch`, `import-amcache`, `import-shimcache`, `import-shellbags`). **Ninguno ha sido validado contra un artefacto real**, salvo Prefetch (225 archivos Windows 10 reales de la imagen OWL 2019).

Todos se auditaron y todos emitían valores equivocados mientras sus tests pasaban. Detalle completo en [`docs/red-team/`](docs/red-team/):

| Adaptador | Auditoría | Hallazgo central |
|-----------|-----------|------------------|
| MFT | `NIVEL6_MFT_AUDIT.md` | Reportaba la fecha de **creación** como de modificación |
| Prefetch | `NIVEL6_PREFETCH_AUDIT.md` | Decodificaba caracteres del nombre de archivo como FILETIME |
| Amcache | `NIVEL6_AMCACHE_AUDIT.md` | Convertía `bytes(range(64))` en la fecha 3204-10-05; salía 0 sin hive |
| Shimcache | `NIVEL6_SHIMCACHE_AUDIT.md` | Consumía un valor de registro ajeno y culpaba al formato |
| Shellbags | `NIVEL6_SHELLBAGS_AUDIT.md` | Devolvía `C:\Users\Bob\Deskto`; 0 de 200 carpetas recuperadas |
| Infraestructura | `NIVEL6_INFRA_AUDIT.md` | El verificador implementaba un subconjunto de su propio protocolo |

### Lo que falta, y qué se necesita

**Requiere un Windows vivo** (imposible en Linux):

- [ ] Nivel 1: validar generación, retención y rollover observing un sistema real.
- [ ] Nivel 4: corpus de calibración con verdad conocida.
- [ ] `lab/collect_windows_baseline.ps1` sobre PowerShell 5.1.

**Requiere solo el archivo** (se copia del volumen; no hace falta licencia ni VM):

- [ ] Un `$MFT` genuino de un volumen adquirido → cierra la mayor brecha de validación.
- [ ] Un `Amcache.hve` genuino. Ni `python-registry` ni `regipy` pueden crear uno, así que no se pudo sintetizar un fixture.
- [ ] Un `SYSTEM`, `NTUSER.DAT` o `UsrClass.dat` genuino.
- [ ] Un `.pf` de Windows XP-8.1 para validar el camino SCCA de Prefetch, que hoy está delegado a libscca y sin verificar.

Los cuatro últimos ítems son **copiar un archivo**. El primero de ellos es el de mayor valor.
