#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later

import re
import sys
from pathlib import Path
from typing import IO


def process_sym_file(file: IO[str]) -> None:
    for line in file:
        m = re.search(r'^\s+([a-zA-Z0-9_]+);', line)
        if m:
            print(f'        {{ "{m[1]}", {m[1]} }},')


def include_name(header: str) -> str:
    path = Path(header)

    if path.name.startswith("libnvme"):
        return path.name

    parts = path.parts
    if "nvme" in parts:
        idx = parts.index("nvme")
        return "/".join(parts[idx:])

    return path.name


def iter_header_statements(file: IO[str]) -> list[str]:
    text = re.sub(r'/\*.*?\*/', '', file.read(), flags=re.S)
    statements = []
    current = []
    brace_depth = 0

    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith('#'):
            continue

        if brace_depth:
            brace_depth += line.count('{') - line.count('}')
            continue

        if not current:
            if line[:1].isspace():
                continue
            if stripped.startswith(('typedef', 'extern "C"')):
                continue
            if stripped.startswith(('struct ', 'enum ', 'union ')) and '(' not in stripped:
                continue

        current.append(stripped)
        statement = ' '.join(current)

        if '{' in statement:
            brace_depth = statement.count('{') - statement.count('}')
            current = []
            continue

        if ';' not in statement:
            continue

        statements.append(statement)
        current = []

    return statements


def process_header_file(file: IO[str]) -> str:
    text = ''

    for statement in iter_header_statements(file):
        if statement.startswith(('}', 'static ', 'typedef ')):
            continue
        if statement.startswith(('struct ', 'enum ', 'union ')) and '(' not in statement:
            continue

        statement = re.sub(r'\s*__attribute__\s*\(\(.*?\)\)', '', statement)
        statement = re.sub(r'\s+', ' ', statement).strip()

        m = re.search(r'^(\S+\s+)+\**(\w+)\s*\(', statement)
        if m:
            if not m[2].startswith(('nvme_', 'nvmf_')):
                continue
            text += f'        {{ "{m[2]}", {m[2]} }},\n'

    return text


print('''/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

''')

for header in sys.argv[2:]:
    with open(header, 'r') as f:
        if process_header_file(f):
            print(f'#include <{include_name(header)}>')

print('''
/* We want to check deprecated symbols too, without complaining. */
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
''')

print('''
struct symbol {
        const char *name;
        const void *symbol;
};
static struct symbol symbols_from_sym[] = {''')

with open(sys.argv[1], 'r') as f:
    process_sym_file(f)

print('''        {}
}, symbols_from_header[] = {''')

for header in sys.argv[2:]:
    with open(header, 'r') as f:
        print(process_header_file(f), end='')

print('''        {}
};

static int sort_callback(const void *a, const void *b) {
        const struct symbol *x = a, *y = b;
        return strcmp(x->name, y->name);
}

int main(void) {
        size_t size = sizeof(symbols_from_sym[0]),
                n_sym = sizeof(symbols_from_sym)/sizeof(symbols_from_sym[0]) - 1,
                n_header = sizeof(symbols_from_header)/sizeof(symbols_from_header[0]) - 1;

        qsort(symbols_from_sym, n_sym, size, sort_callback);
        qsort(symbols_from_header, n_header, size, sort_callback);

        puts("From symbol file:");
        for (size_t i = 0; i < n_sym; i++)
                printf("%p: %s\\n", symbols_from_sym[i].symbol, symbols_from_sym[i].name);

        puts("\\nFrom header files:");
        for (size_t i = 0; i < n_header; i++)
                printf("%p: %s\\n", symbols_from_header[i].symbol, symbols_from_header[i].name);

        puts("");
        printf("Found %zu symbols from symbol file.\\n", n_sym);
        printf("Found %zu symbols from header files.\\n", n_header);

        unsigned n_error = 0;

        for (size_t i = 0; i < n_sym; i++)
                if (!bsearch(symbols_from_sym+i, symbols_from_header, n_header, size, sort_callback)) {
                        printf("Found in symbol file, but not in headers: %s\\n", symbols_from_sym[i].name);
                        n_error++;
                }

        for (size_t i = 0; i < n_header; i++)
                if (!bsearch(symbols_from_header+i, symbols_from_sym, n_sym, size, sort_callback)) {
                        printf("Found in header file, but not in symbol file: %s\\n", symbols_from_header[i].name);
                        n_error++;
                }

        return n_error == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}''')
