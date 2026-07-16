# -*- coding: utf-8 -*-
"""
redteam_pii.py — BANCO DE EVASION (§6) del Portero de PII saliente. Escrito EN ROJO.

Autor: verificador-programador (enjambre TechAcces). 11/07/2026.

POR QUE ESTE FICHERO EXISTE APARTE DE run_tests_pii.py
------------------------------------------------------
Leccion del 10/07: el guardian `guardian_mysql` tenia un banco VERDE de 15 casos
felices y AUN ASI fallo ABIERTO ante un DROP escondido en un comentario ejecutable.
Lo cazo el red-team, no el banco feliz. Aqui la prueba real del portero de PII es
la EVASION, no los casos limpios: el detector solo se acepta si sobrevive a esto.

Cada caso ataca una via de evasion distinta del §6 del spec. Todos deben terminar
en BLOQUEO (o, el unico caso "trampa", en PASE deliberado: el guardarrail de falso
positivo). El objetivo es fijar el LISTON antes de que exista el detector.

Estado esperado HOY: ROJO LIMPIO — `portero_pii.py` no existe, luego todos los
casos fallan por ImportError/ModuleNotFoundError.

Contrato de interfaz: definido en la cabecera de run_tests_pii.py (fuente unica).
Resumen usado aqui: analizar(entrada, deny_list) -> Resultado(.bloquear, .clases, .motivo).
CERO PII real: la deny-list es un FIXTURE de nombres INVENTADOS.
"""

import os
import sys
import unittest
import tempfile
import pathlib

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Mismo fixture INVENTADO que la suite de aceptacion (0 PII real).
DENY_LIST = [
    "Fulano Menganez",
    "Zutana Perez",
    "Perengano De Tal",
    "Mengana Lopez Sanz",
    "Robustiano Garcia",
]

IBAN_TEST = "ES91 2100 0418 4502 0005 1332"
IBAN_COMPACTO = IBAN_TEST.replace(" ", "")


def _analizar(entrada, deny_list=None):
    """Import DENTRO del test: la ausencia del detector se manifiesta por-caso."""
    import portero_pii  # noqa: F401  -> HOY ModuleNotFoundError a proposito
    return portero_pii.analizar(entrada, DENY_LIST if deny_list is None else deny_list)


class RedTeamNombres(unittest.TestCase):
    """Evasiones sobre el nombre de la deny-list."""

    def test_r01_nombre_partido_en_dos_lineas(self):
        # "Fulano\nMenganez": el salto de linea NO debe romper la deteccion.
        texto = "Firmado por Fulano\nMenganez, con fecha de hoy."
        r = _analizar(texto)
        self.assertTrue(r.bloquear)
        self.assertIn("nombre_denylist", r.clases)

    def test_r02_nombre_con_iniciales(self):
        # "F. Menganez": abreviar el nombre de pila no debe permitir la fuga.
        texto = "El expediente lo lleva F. Menganez desde marzo."
        r = _analizar(texto)
        self.assertTrue(r.bloquear)
        self.assertIn("nombre_denylist", r.clases)

    def test_r03_nombre_con_acentos_cambiados(self):
        # "Fulano Menganez" atacado con tildes ("Fulano Menganez" -> "Fúlano
        # Ménganez"): normalizacion de diacriticos obligatoria (comparar sin tildes).
        texto_atacado = "Remitente: Fúlano Ménganez, con acentos."
        r = _analizar(texto_atacado)
        self.assertTrue(r.bloquear)
        self.assertIn("nombre_denylist", r.clases)

    def test_r04_nombre_en_mayusculas(self):
        # "FULANO MENGANEZ": comparacion insensible a mayusculas/minusculas.
        texto = "REMITENTE: FULANO MENGANEZ. ASUNTO: nomina."
        r = _analizar(texto)
        self.assertTrue(r.bloquear)
        self.assertIn("nombre_denylist", r.clases)

    def test_r05_seudonimizacion_a_medias_9_de_10(self):
        # 9 empleados seudonimizados, 1 nombre real de la deny-list colado.
        lineas = [f"EMP{n:03d} ... {1800 + n*10},00" for n in range(1, 10)]
        lineas.insert(4, "Mengana Lopez Sanz ... 2.010,50")  # el colado (con locale)
        texto = "Nomina lote (seudonimizada):\n" + "\n".join(lineas)
        r = _analizar(texto)
        self.assertTrue(r.bloquear)
        self.assertIn("nombre_denylist", r.clases)


class RedTeamNumerosYLocale(unittest.TestCase):
    """Locale es-ES e identificadores con separadores."""

    def test_r06_importe_locale_es_es_no_es_pii(self):
        # GUARDARRAIL DE FALSO POSITIVO (el unico caso que debe PASAR):
        # "1.234,56 €" es un importe con formato es-ES, NO un NIF/DNI/IBAN.
        # Un regex ingenuo que cace grupos de digitos daria falso positivo aqui.
        texto = "El total de la factura asciende a 1.234,56 EUR por los servicios."
        r = _analizar(texto)
        self.assertFalse(r.bloquear)
        self.assertEqual(r.clases, [])

    def test_r07_iban_con_espacios(self):
        # IBAN con los espacios de agrupacion tipicos -> debe bloquear.
        texto = f"Pago a la cuenta {IBAN_TEST}."
        r = _analizar(texto)
        self.assertTrue(r.bloquear)
        self.assertIn("iban", r.clases)

    def test_r08_iban_compacto_en_minusculas(self):
        # Sin espacios y en minusculas ("es91..."): normalizar antes de validar.
        texto = f"cuenta: {IBAN_COMPACTO.lower()} (sin formato)"
        r = _analizar(texto)
        self.assertTrue(r.bloquear)
        self.assertIn("iban", r.clases)

    def test_r09_nif_con_guiones_y_puntos(self):
        # "12.345.678-Z": puntos de millar + guion antes de la letra -> bloquear.
        texto = "Documento del interesado: 12.345.678-Z, segun consta."
        r = _analizar(texto)
        self.assertTrue(r.bloquear)
        self.assertIn("nif", r.clases)

    def test_r10_nif_con_espacios(self):
        # "12345678 Z": espacio entre numero y letra de control -> bloquear.
        texto = "DNI aportado: 12345678 Z en el formulario."
        r = _analizar(texto)
        self.assertTrue(r.bloquear)
        self.assertIn("nif", r.clases)


class RedTeamFalloCerrado(unittest.TestCase):
    """Encoding / ilegibilidad: ante la duda, se BLOQUEA."""

    def test_r11_fichero_latin1_no_utf8_falla_cerrado(self):
        # Fichero codificado en latin-1 con bytes invalidos como UTF-8. Aunque
        # el detector no pueda leer el contenido, DEBE fallar CERRADO (bloquear),
        # nunca dejar pasar lo que no ha podido inspeccionar.
        fd, ruta = tempfile.mkstemp(suffix=".txt")
        os.close(fd)
        try:
            # FIX fixture (11/07): el contenido anterior llevaba — y €, no codificables
            # en latin-1, y reventaba al ESCRIBIR (antes de tocar el detector). Uso una
            # 'a' acentuada: byte 0xE1 en latin-1, invalido como UTF-8 -> prueba real de fail-closed.
            contenido = "Nomina de Fulano Mengánez importe 1990 EUR"
            with open(ruta, "w", encoding="latin-1") as fh:
                fh.write(contenido)
            r = _analizar(pathlib.Path(ruta))
            self.assertTrue(r.bloquear)
            self.assertIn("ilegible", r.clases)
            # Y ni siquiera al fallar debe filtrar el nombre en el motivo.
            self.assertNotIn("Fulano Menganez", r.motivo)
        finally:
            os.remove(ruta)


# -----------------------------------------------------------------------------
# Runner: confirma ROJO LIMPIO.
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
    print(f"Total de casos de EVASION    : {total}")
    print(f"Fallan por ausencia detector : {por_detector}")
    print(f"Pasan                        : {pasaron}")
    if len(incidencias) == 0:
        print("VEREDICTO: VERDE — el portero resiste los %d intentos de evasion; "
              "ninguno logra fuga." % total)
    elif pasaron == 0 and por_detector == total:
        print("VEREDICTO: ROJO LIMPIO — el banco de evasion falla en bloque por no "
              "existir portero_pii.py (fase pre-constructor, ya superada).")
    else:
        print("VEREDICTO: MIXTO — revisar: %d evasiones no bloqueadas o fallos "
              "ajenos (%d por ausencia del detector)." % (len(incidencias), por_detector))
    print("=" * 70)
    sys.exit(0 if result.wasSuccessful() else 1)


if __name__ == "__main__":
    main()
