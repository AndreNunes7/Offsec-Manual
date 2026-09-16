#!/usr/bin/env node
// Valida a sintaxe do bloco <script> do index.html SEM executá-lo.
// Uso: node scripts/check-syntax.js
// Motivo (ver CLAUDE.md, seção Development): editar o array STEPS à mão e esquecer uma
// vírgula quebra o app inteiro silenciosamente — este script pega isso em 1 comando.
'use strict';

const fs = require('fs');
const path = require('path');

const file = path.join(__dirname, '..', 'index.html');
const html = fs.readFileSync(file, 'utf8');

const OPEN = '<script>';
const CLOSE = '</script>';
const start = html.indexOf(OPEN);
const end = html.lastIndexOf(CLOSE);
if (start === -1 || end === -1) {
  console.error('ERRO: delimitadores <script>/</script> não encontrados em index.html');
  process.exit(1);
}

const code = html.slice(start + OPEN.length, end);
const scriptLine = html.slice(0, start + OPEN.length).split('\n').length;

try {
  new Function(code);
} catch (e) {
  const relLine = e.lineNumber || 0;
  console.error('ERRO de sintaxe em index.html:');
  console.error('  ' + e.message);
  if (relLine) console.error('  linha aprox.: ' + (scriptLine + relLine) + ' (relativa ao <script>: ' + relLine + ')');
  process.exit(1);
}

console.log('OK — sintaxe do <script> válida (' + code.split('\n').length + ' linhas).');
