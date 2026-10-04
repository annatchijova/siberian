# Pendientes de SIBERIAN

Actualizado: 2026-10-04

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

- [ ] Nivel 2: persistir y verificar informes desde la instalación CLI; la lectura inicial de casos y `validate` / `analyze` / `explain` ya está implementada.
- [ ] Nivel 3: hipótesis rivales, dependencias de artefactos y contrafácticos explícitos.
- [ ] Nivel 4: evaluación empírica ciega y calibración, solo si los datos discriminan las hipótesis.
- [ ] Nivel 5: bundle sellado y verificador independiente.
- [ ] Nivel 6: adaptadores de importación para herramientas forenses elegidas con usuarios. Decisión inicial para Plaso documentada en [`docs/PLASO_IMPORT.md`](docs/PLASO_IMPORT.md): solo presencias con mapeo explícito; una fila ausente no prueba ausencia. Falta validar el diseño con analistas antes de implementar.
