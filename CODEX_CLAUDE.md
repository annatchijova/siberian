# SIBERIAN — problemas y próximos pasos

Actualizado: 2026-10-04  
Estado: revisión de diseño y pruebas unitarias iniciales; no es una auditoría completa.

## Problemas abiertos

| Prioridad | Problema | Efecto | Próximo paso |
| --- | --- | --- | --- |
| Alta | El catálogo tiene cinco entradas documentadas para Windows 10, pero no una matriz mantenida por build, edición y configuración dentro de esa familia. | Una ausencia exige build declarado y atestación referenciada de aplicabilidad, pero el código no coteja esa atestación contra una matriz verificada. | Elegir builds/configuraciones objetivo, documentar compatibilidad por entrada y rechazar o marcar como no cubiertas las combinaciones sin fuente. |
| Alta | Las condiciones se acreditan mediante referencias que escribe el caller; SIBERIAN no abre ni comprueba los recursos referenciados. | Una referencia presente no prueba que la auditoría estuviera habilitada, que el log cubra el intervalo o que el USN journal no haya rotado. | Mantener el lenguaje como afirmación del analista; para el Nivel 2 definir manifiesto con hashes, tipos de fuente y cobertura verificable. |
| Alta | La cobertura temporal por condición tiene intervalos tipados, pero las fuentes siguen siendo referencias y declaraciones del analista. | El programa rechaza evidencia declarada que no cubra todo el intervalo analizado, pero no abre los recursos ni verifica que su contenido pruebe esa cobertura. | Mantener esta limitación explícita; en el manifiesto del Nivel 2 añadir tipos de fuente y hashes y decidir cuáles se pueden verificar localmente. |
| Media | El catálogo de 5156 usa documentación de Windows 10 y todavía no declara compatibilidad por build. | No debe generalizarse su semántica o volumen de eventos más allá del alcance documentado. | Validar documentación para cada build objetivo y acotar `scope` mientras tanto. |
| Media | El catálogo aún no tiene evaluación empírica de persistencia o pérdida benigna. | Las expectativas son condicionales y documentadas, pero no estiman qué suele sobrevivir en campo. | Diseñar casos controlados de pérdida benigna y adquisición con procedencia conocida; reportar límites antes de proponer scores. |
| Media | Las pruebas actuales cubren trece casos del núcleo, pero no adaptadores, esquema de expediente ni corpus empírico. | Los resultados verdes solo respaldan los casos unitarios implementados. | Ampliar pruebas al estabilizar el manifiesto y crear un corpus independiente; no afirmar validación forense por pasar unit tests. |
| Media | `audit_hash` es un digest reproducible, no una firma ni una cadena de custodia. | No acredita quién produjo los datos ni su integridad desde la adquisición. | En niveles posteriores definir bundle, firma opcional, sellado temporal y verificador independiente. |
| Baja | No hay CLI ni formato de expediente portable. | La biblioteca requiere que otro programa arme el contexto y las observaciones. | Construir el manifiesto/CLI en el Nivel 2, después de fijar el esquema y sus límites de confianza. |
| Baja | No hay hipótesis rivales, contrafácticos ni evidencia pivote calculada. | El núcleo organiza observaciones, pero no discrimina pérdida benigna, retención, brecha de sensor o borrado selectivo. | Diseñar esos modelos en el Nivel 3 sin convertir ausencia aislada en intención. |

## Aclaraciones de diseño

- No se mantienen los pesos ordinales heredados ni se publica un score de sospecha sin evaluación y calibración.
- `CONFIRMED_ABSENT` significa que el analista declaró ausencia y aportó referencias para las condiciones; el código valida la forma de la declaración, no la verdad de sus fuentes.
- El contexto de sistema se incorpora al digest. La normalización temporal convierte timestamps con zona a UTC; los timestamps sin zona y los intervalos invertidos se rechazan.
- El digest no demuestra que el expediente sea completo, correcto o auténtico.
- Windows es el único perfil habilitado. Las entradas Linux del seed siguen diferidas.

## Verificación conocida

Última ejecución: `python3 -m unittest discover -s tests -v` — 14 pruebas pasaron después de añadir la atestación de build al gate de ausencia.  
También pasaron `python3 -m compileall -q siberian tests` y `git diff --check`.  
Esto no valida el catálogo empíricamente ni prueba hipótesis forenses.

## Siguiente trabajo

1. Definir releases de Windows admitidos y completar fuentes por artefacto.
2. Cambiar condiciones temporales de texto libre a intervalos y cobertura tipados, o declarar explícitamente que son atestaciones del analista.
3. Añadir una política de compatibilidad del catálogo para que un release desconocido no parezca cubierto.
4. Volver a revisar el plan del Nivel 1 y sus pruebas antes de iniciar el expediente/CLI del Nivel 2.
