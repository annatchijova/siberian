# SIBERIAN

[English](README.md) · **Español** · [README técnico](TECHNICAL_README.md)

## Análisis de silencio adversarial

**Lo que desapareció también puede ser evidencia.**

Las investigaciones digitales suelen empezar por los artefactos que sobrevivieron a la adquisición. SIBERIAN aborda la pregunta complementaria: dado un hecho y el alcance de la adquisición, ¿qué artefactos deberían haberse podido observar y qué podría explicar los que faltan?

El proyecto está en etapa inicial. La primera implementación comparará ausencias confirmadas con artefactos supervivientes y explicaciones alternativas. Devolverá `ABSTAIN` cuando la evidencia disponible no permita distinguir entre borrado selectivo, pérdida benigna o una brecha de adquisición.

```text
Informe ilustrativo — no es el resultado de un analizador implementado

OBSERVADO
  Prefetch             ausencia confirmada
  USN Journal          desconocido (no adquirido)
  Caché DNS            presente

RESULTADO
  Evidencia insuficiente para distinguir borrado selectivo
  de efectos de retención o adquisición.

VEREDICTO: ABSTAIN
```

La ausencia por sí sola no demuestra borrado, manipulación, atribución ni intención. El diseño técnico y sus límites conocidos están en el **[README técnico](TECHNICAL_README.md)**.

## Qué aporta la pregunta

| Revisión habitual de evidencia | Análisis previsto por SIBERIAN |
| --- | --- |
| Enumera los artefactos encontrados | También modela los esperados y su estado de observación |
| Puede tratar un registro faltante como un vacío | Separa presente, ausencia confirmada, desconocido y fuera de alcance |
| Puede reducir el resultado a una explicación | Conserva explicaciones rivales y puede abstenerse |

Son objetivos de diseño; no son capacidades de una versión publicada.

## Estado y origen

SIBERIAN parte de la idea 24 del catálogo de **40** ideas de productos de VIGÍA: «Detector de silencio adversarial (el borrado selectivo delata)». La nota de origen registra el concepto y los módulos iniciales: [`vigia/patterns/adversarial_silence.py`](docs/VIGIA_20_IDEAS_2026-08-13.md) y `vigia/tools/temporal_drift.py`, en el proyecto independiente `vigia-repo`.

El detector de VIGÍA es un punto de partida de investigación, no un producto independiente validado. SIBERIAN busca convertirse en un proyecto Python autónomo, sin dependencia de ejecución de VIGÍA.

## Primera etapa prevista

- Manifiesto tipado de evidencia con estados explícitos de observación y adquisición.
- Comparación determinista entre artefactos esperados y observaciones confirmadas.
- Hipótesis rivales, sugerencias de investigación y resultados `PASS` / `WARN` / `ABSTAIN`.
- Informe canónico con procedencia y hash de contenido.
- CLI pequeña para manifiestos aportados por el usuario.

Todavía no hay una CLI independiente ni inferencia lista para producción. Aún no se eligieron licencia ni términos de contribución.

> La evidencia no es solamente lo que permanece.
