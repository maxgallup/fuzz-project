import os
import r2pipe
import sqlite3

def init_database():
    os.system("rm line.db")
    conn = sqlite3.connect("line.db")
    cursor = conn.cursor()
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS library_data (
        library_name TEXT PRIMARY KEY
    )
''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS symbols (
            symbol_name TEXT,
            library_name TEXT,
            FOREIGN KEY (library_name) REFERENCES library_data (library_name)
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS exports (
            export_name TEXT,
            library_name TEXT,
            FOREIGN KEY (library_name) REFERENCES library_data (library_name)
        )
    ''')
    conn.commit()
    return conn


def get_libraries(directory_path):
    return [os.path.join(directory_path, file) for file in os.listdir(directory_path)
                if file.endswith(".so")]

def get_exports(r2):
    exports = []
    for export in r2.cmdj("iEj"):
        if "demname" in export:
            exports.append(export["demname"])
        else:
            exports.append(export["name"])
    return exports


def get_symbols(r2):
    symbols = []
    for symbol in r2.cmdj("isj"):
        if "demname" in symbol:
            symbols.append(symbol["demname"])
        else:
            symbols.append(symbol["name"])
    return symbols

def main():
    conn = init_database()
    libraries = get_libraries("./line-14-8-0/lib/armeabi-v7a")
    for library_path in libraries:
        r2 = r2pipe.open(library_path)
        library = os.path.basename(library_path)
        print(library)
        cursor = conn.cursor()
        cursor.execute("INSERT INTO library_data (library_name) VALUES (?)", (library, ))
        for export in get_exports(r2):
            cursor.execute(f'''
            INSERT INTO exports (export_name, library_name) VALUES
            (?, ?)
            ''', (export, library))
        conn.commit()
        cursor = conn.cursor()
        for symbol in get_symbols(r2):
            cursor.execute('''
            INSERT INTO symbols (symbol_name, library_name) VALUES
            (?, ?)
            ''', (symbol, library))
        conn.commit()
        r2.quit()

if __name__ == "__main__":
    main()

