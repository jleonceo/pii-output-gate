# -*- coding: utf-8 -*-
"""
run_tests_pii.py — SUITE DE ACEPTACION (escrita EN ROJO) del Portero de PII saliente.

Autor: verificador-programador (enjambre TechAcces). 11/07/2026.
Esta suite se escribio ANTES que el detector, para fijar el liston sin conocer la
implementacion. En aquel momento el estado esperado era ROJO LIMPIO: `portero_pii.py`
no existia y todos los tests fallaban por ImportError, no por errores del propio test.
El detector lo escribio despues otra persona, contra este contrato. Hoy la suite esta
en VERDE, y por eso sigue aqui: lo que fija el liston no se retoca al implementarlo.

===============================================================================
CONTRATO DE INTERFAZ (el constructor queda RESTRINGIDO a esto)
===============================================================================
Modulo:   portero_pii.py  (stdlib pura, sin dependencias externas)

Funcion:  analizar(entrada, deny_list) -> Resultado

  entrada   : str  -> se interpreta como TEXTO literal a inspeccionar.
              pathlib.Path (o os.PathLike) -> se interpreta como RUTA de fichero
              cuyo contenido se lee e inspecciona. Regla de desambiguacion:
              un `str` SIEMPRE es texto (aunque parezca una ruta); para forzar
              semantica de fichero se pasa un Path. Asi los tests son inequivocos.
  deny_list : list[str] -> nombres reales CONOCIDOS (personas) que deben bloquearse.
              En estos tests es un FIXTURE de nombres INVENTADOS (0 PII real).

Resultado (objeto/dataclass/namedtuple; se accede por atributo):
  .bloquear : bool          -> True = NO puede salir; False = PASA.
  .clases   : list[str]     -> etiquetas de lo detectado. Vocabulario CERRADO:
                               "nombre_denylist", "iban", "nif", "ilegible".
                               (NIF y DNI comparten la etiqueta "nif".)
                               Vacia si .bloquear es False.
  .motivo   : str           -> explicacion legible. INVARIANTE DURO: NUNCA contiene
                               el valor de PII en claro (ni el nombre, ni el IBAN,
                               ni el NIF). Un log que "ayuda" es la fuga.

Comportamiento contractual exigido por esta suite:
  - Falla CERRADO: si la entrada (fichero) no se puede leer/parsear como UTF-8
    (encoding latin-1, binario), analizar() DEBE devolver .bloquear=True con
    clase "ilegible". NO lanza excepcion al llamador: la traduce a bloqueo.
  - Override FUERA DE BANDA (cambio de contrato 11/07): la antigua valvula inline
    `# pii:allow <motivo>` DENTRO del texto se ELIMINA (era un vector de fail-open;
    ver regresion_pii.py g02/g07/g10). El override pasa a ser un parametro EXPLICITO
    de analizar(), justificado por el LLAMADOR:

        analizar(entrada, deny_list, *, override=False, override_justificacion=None)

    override=True con override_justificacion no vacia -> .bloquear=False. La
    justificacion la aporta el llamador (auditoria externa), NO se deriva del
    `entrada` escaneado. Un `# pii:allow` que aparezca en el contenido es DATO y
    NO desactiva nada.
===============================================================================
"""

import os
import sys
import unittest
import tempfile
import pathlib

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# --- Fixture: deny-list de nombres 100% INVENTADOS (CERO PII real) -----------
# Ninguno corresponde a persona alguna. Son marcadores para el test.
DENY_LIST = [
    "Fulano Menganez",
    "Zutana Perez",
    "Perengano De Tal",
    "Mengana Lopez Sanz",
    "Robustiano Garcia",
]

# IBAN de prueba estandar (no pertenece a ninguna cuenta real).
IBAN_TEST = "ES91 2100 0418 4502 0005 1332"
# DNI de formato valido (numero generico, letra de control correcta).
NIF_TEST = "12345678Z"


def _analizar(entrada, deny_list=None):
    """Carga el detector DENTRO de cada test para que su ausencia se manifieste
    como ImportError por-test (rojo limpio) y no como fallo de coleccion global."""
    import portero_pii  # noqa: F401  -> HOY lanza ModuleNotFoundError a proposito
    return portero_pii.analizar(entrada, DENY_LIST if deny_list is None else deny_list)


class TestDebenBloquear(unittest.TestCase):
    """Casos §5 (a-e): el portero DEBE bloquear."""

    def test_a_nombre_real_denylist_en_texto_libre(self):
        texto = "Adjunto el resumen del caso de Fulano Menganez para su revision."
        r = _analizar(texto)
        self.assertTrue(r.bloquear)
        self.assertIn("nombre_denylist", r.clases)

    def test_b_iban_es(self):
        texto = f"Transferir al numero de cuenta {IBAN_TEST} antes del viernes."
        r = _analizar(texto)
        self.assertTrue(r.bloquear)
        self.assertIn("iban", r.clases)

    def test_c_nif_dni(self):
        texto = f"El titular figura con documento {NIF_TEST} en el expediente."
        r = _analizar(texto)
        self.assertTrue(r.bloquear)
        self.assertIn("nif", r.clases)

    def test_d_nomina_seudonimizada_con_nombre_colado(self):
        # 4 lineas seudonimizadas correctamente + 1 nombre real que se colo.
        texto = (
            "Nomina lote junio (seudonimizada):\n"
            "EMP001 ... 1.850,00\n"
            "EMP002 ... 2.100,00\n"
            "Zutana Perez ... 1.990,00\n"   # <- se colo un nombre de la deny-list
            "EMP004 ... 2.240,00\n"
        )
        r = _analizar(texto)
        self.assertTrue(r.bloquear)
        self.assertIn("nombre_denylist", r.clases)

    def test_e_entrada_ilegible_falla_cerrado(self):
        # Fichero con bytes latin-1 invalidos como UTF-8 -> debe bloquear (fail closed).
        fd, ruta = tempfile.mkstemp(suffix=".txt")
        os.close(fd)
        try:
            with open(ruta, "wb") as fh:
                fh.write(b"Facturaci\xf3n del cliente n\xba 5")  # 0xF3, 0xBA no-UTF8
            r = _analizar(pathlib.Path(ruta))
            self.assertTrue(r.bloquear)
            self.assertIn("ilegible", r.clases)
        finally:
            os.remove(ruta)


class TestDebenPasar(unittest.TestCase):
    """Casos §5 (f-h): el portero DEBE dejar pasar."""

    def test_f_texto_sin_pii(self):
        texto = "El informe trimestral de ventas muestra una mejora del margen bruto."
        r = _analizar(texto)
        self.assertFalse(r.bloquear)
        self.assertEqual(r.clases, [])

    def test_g_nombre_comun_no_en_denylist(self):
        # "Antonio Sanchez": nombre comun generico, DELIBERADAMENTE ausente de la
        # deny-list. La capa A (determinista) NO bloquea lo que no conoce; eso es
        # trabajo de la capa B (NER, diferida). No identifica a nadie: es un token.
        texto = "El ponente invitado fue Antonio Sanchez, del area de operaciones."
        r = _analizar(texto)
        self.assertFalse(r.bloquear)
        self.assertNotIn("nombre_denylist", r.clases)

    def test_h_override_fuera_de_banda(self):
        # RETIRADO el test antiguo de la valvula INLINE (`# pii:allow` en el texto):
        # no es una relajacion del banco, es que el VECTOR desaparece. Un marcador
        # dentro del contenido saliente era fail-open (lo demuestran g02/g07/g10 en
        # regresion_pii.py). El override legitimo va ahora FUERA DE BANDA: parametro
        # explicito de analizar(), justificado por el llamador, NUNCA embebido en el
        # texto inspeccionado.
        #
        # Depende de la NUEVA FIRMA: hoy da TypeError (analizar solo acepta 2 args)
        # -> ROJO por firma pendiente, no por sintaxis. El constructor la implementa.
        import portero_pii
        texto = "Publicar ficha anonimizada de Fulano Menganez."  # PII de la deny-list
        r = portero_pii.analizar(
            texto, DENY_LIST,
            override=True,
            override_justificacion="revisado y anonimizado por el DPO 11/07",
        )
        self.assertFalse(r.bloquear)
        # El override no filtra: la justificacion es del llamador, no del input.
        self.assertNotIn("Fulano Menganez", r.motivo)


class TestInvarianteNoFuga(unittest.TestCase):
    """Invariante duro §3/§37: el motivo NUNCA revela el PII en claro."""

    def test_motivo_no_contiene_pii_en_claro(self):
        texto = f"Cuenta {IBAN_TEST} a nombre de Fulano Menganez, DNI {NIF_TEST}."
        r = _analizar(texto)
        self.assertTrue(r.bloquear)
        # Ni el nombre, ni el IBAN (compacto), ni el NIF pueden aparecer en el motivo.
        self.assertNotIn("Fulano Menganez", r.motivo)
        self.assertNotIn(IBAN_TEST.replace(" ", ""), r.motivo)
        self.assertNotIn(NIF_TEST, r.motivo)


# -----------------------------------------------------------------------------
# Runner: confirma ROJO LIMPIO (todos fallan por ausencia del detector).
# -----------------------------------------------------------------------------
def _es_por_ausencia_detector(traza: str) -> bool:
    marcas = ("ModuleNotFoundError", "No module named 'portero_pii'",
              "ImportError", "portero_pii")
    return any(m in traza for m in marcas)


def main():
    suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])
    total = suite.countTestCases()
    result = unittest.TextTestRunner(verbosity=2).run(suite)

    incidencias = list(result.errors) + list(result.failures)
    por_detector = sum(1 for _, tb in incidencias if _es_por_ausencia_detector(tb))
    pasaron = total - len(incidencias)

    print("\n" + "=" * 70)
    print(f"Total de casos de aceptacion : {total}")
    print(f"Fallan por ausencia detector : {por_detector}")
    print(f"Pasan                        : {pasaron}")
    if len(incidencias) == 0:
        print("VEREDICTO: VERDE — portero_pii.py presente y los %d casos de "
              "aceptacion pasan; el invariante se sostiene." % total)
    elif pasaron == 0 and por_detector == total:
        print("VEREDICTO: ROJO LIMPIO — la suite falla en bloque por no existir "
              "portero_pii.py (fase pre-constructor, ya superada).")
    else:
        print("VEREDICTO: MIXTO — revisar: %d incidencias, %d por ausencia del "
              "detector; el resto son fallos reales." % (len(incidencias), por_detector))
    print("=" * 70)
    sys.exit(0 if result.wasSuccessful() else 1)


if __name__ == "__main__":
    main()
