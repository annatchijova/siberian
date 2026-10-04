# SIBERIAN

[English](README.md) · **Español** · [README técnico](TECHNICAL_README.md)

## Análisis de silencio adversarial

**Lo que desapareció también puede ser evidencia.**

Las investigaciones digitales suelen empezar por los artefactos que sobrevivieron a la adquisición. SIBERIAN aborda la pregunta complementaria: dado un hecho y el alcance de la adquisición, ¿qué artefactos deberían haberse podido observar y qué podría explicar los que faltan?

La primera biblioteca de análisis en Python ya está portada. Compara las ausencias confirmadas con los demás artefactos esperados para una acción. Devuelve métricas descriptivas exactas y un hash de las entradas del análisis; no clasifica intención ni produce un veredicto.

```python
from siberian import AdversarialSilenceDetector, ArtifactStatus

analysis = AdversarialSilenceDetector(os_profile="windows")
analysis.register_primary_action("process_execution")
analysis.register_observation(
    "process_execution", "prefetch_entry", ArtifactStatus.CONFIRMED_ABSENT,
    explanation="Verificado en el directorio Prefetch adquirido",
)
analysis.register_observation(
    "process_execution", "event_4688", ArtifactStatus.PRESENT,
)
result = analysis.analyze()
print(result.selectivity_score, result.known_count, result.audit_hash)
```

Los artefactos sin registrar quedan como `UNKNOWN` y no entran en las métricas. La ausencia por sí sola no demuestra borrado, manipulación, atribución ni intención. El diseño técnico, las fórmulas y los límites están en el **[README técnico](TECHNICAL_README.md)**.

## Qué aporta la pregunta

| Revisión habitual de evidencia | Análisis previsto por SIBERIAN |
| --- | --- |
| Enumera los artefactos encontrados | También modela los esperados y su estado de observación |
| Puede tratar un registro faltante como un vacío | Separa presente, ausencia confirmada, desconocido y fuera de alcance |
| Puede reducir el resultado a una explicación | Devuelve métricas descriptivas, sin veredicto de intención |

La biblioteca actual implementa estados de observación y métricas descriptivas. Todavía no modela hipótesis rivales ni emite resultados `PASS` / `WARN` / `ABSTAIN`.

## Estado y origen

SIBERIAN parte de la idea 24 del catálogo de **40** ideas de productos de VIGÍA: «Detector de silencio adversarial (el borrado selectivo delata)». La nota de origen registra el concepto y los módulos iniciales: [`vigia/patterns/adversarial_silence.py`](docs/VIGIA_20_IDEAS_2026-08-13.md) y `vigia/tools/temporal_drift.py`, en el proyecto independiente `vigia-repo`.

El detector de VIGÍA es un punto de partida de investigación, no un producto independiente validado. SIBERIAN es un paquete Python autónomo, sin dependencia de ejecución de VIGÍA. La adaptación y la licencia de origen están en [`NOTICE`](NOTICE).

## Paquete actual y próximos pasos

- `siberian/`: biblioteca de análisis sin dependencias y catálogos iniciales para Windows/Linux.
- `docs/`: procedencia, comportamiento técnico y decisión de lenguaje.
- Próximo: validar las expectativas de artefactos, crear un formato versionado de manifiesto y luego evaluar hipótesis rivales.

Todavía no hay CLI, modelo calibrado ni corpus de validación. Los pesos descriptivos son supuestos heredados de investigación, no probabilidades. Licencia Apache-2.0.

> La evidencia no es solamente lo que permanece.
