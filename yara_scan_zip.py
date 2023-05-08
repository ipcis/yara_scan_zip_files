import yara
import zipfile

# Definieren Sie Ihre YARA-Regeln als Textzeichenfolge
yara_rules = """
rule suspicious_file
{
    strings:
        $suspicious_string = "evil_code"
    condition:
        $suspicious_string
}
"""

# Kompilieren Sie die YARA-Regeln
rules = yara.compile(source=yara_rules)

# Öffnen Sie das ZIP-Archiv
with zipfile.ZipFile("archive.zip", "r") as zip_file:
    # Schleife durch alle Dateien im Archiv
    for file_info in zip_file.infolist():
        # Lesen Sie den Inhalt der Datei
        with zip_file.open(file_info) as file:
            content = file.read()
        # Scannen Sie den Inhalt mit YARA
        matches = rules.match(data=content)
        # Wenn es Übereinstimmungen gibt, drucken Sie den Dateinamen
        if matches:
            print(file_info.filename)
