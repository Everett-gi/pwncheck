// PwnCheck — verificação no navegador (k-anonymity).
// A senha e o hash completo nunca saem desta página: só o prefixo de 5 caracteres vai ao
// servidor (GET /range/{prefixo}), e a comparação do sufixo acontece aqui.
"use strict";

const form = document.querySelector("#check-form");
const input = document.querySelector("#password");
const steps = document.querySelector("#steps");
const result = document.querySelector("#result");

// SHA-1 em hexadecimal maiúsculo — o mesmo que app/kanonymity.py faz no servidor.
// TextEncoder gera os bytes em UTF-8; crypto.subtle só existe em contexto seguro (HTTPS ou
// localhost).
async function sha1Hex(text) {
  const bytes = new TextEncoder().encode(text);
  const digest = await crypto.subtle.digest("SHA-1", bytes);
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, "0"))
    .join("")
    .toUpperCase();
}

// Procura o sufixo nas linhas "SUFIXO:CONTAGEM" (como parse_range_response, em Python).
function findCount(body, suffix) {
  for (const line of body.split(/\r?\n/)) {
    const [candidate, count] = line.trim().split(":");
    if (candidate === suffix) return Number(count);
  }
  return 0;
}

function show(message, kind) {
  result.textContent = message; // textContent, nunca innerHTML: nada vira HTML
  result.className = `result ${kind}`;
  result.hidden = false;
}

form.addEventListener("submit", async (event) => {
  event.preventDefault(); // não envia o formulário: tudo acontece aqui
  const password = input.value;
  if (!password) return;

  const hash = await sha1Hex(password);
  const prefix = hash.slice(0, 5);
  const suffix = hash.slice(5);
  document.querySelector("#prefix").textContent = prefix;
  document.querySelector("#suffix").textContent = suffix;
  document.querySelector("#sent").textContent = prefix;
  document.querySelector("#received").textContent = "…";
  steps.hidden = false;

  let response;
  try {
    response = await fetch(`/range/${prefix}`);
  } catch {
    show("Não foi possível falar com o servidor. Verifique sua conexão.", "error");
    return;
  }
  if (!response.ok) {
    show("A base de vazamentos não respondeu agora. Tente de novo em instantes.", "error");
    return;
  }

  const body = await response.text();
  const total = body ? body.split(/\r?\n/).length : 0;
  document.querySelector("#received").textContent = total.toLocaleString("pt-BR");

  const count = findCount(body, suffix);
  if (count > 0) {
    show(`Esta senha apareceu ${count.toLocaleString("pt-BR")} vezes em vazamentos. Não use!`, "bad");
  } else {
    show("Esta senha não aparece na base de vazamentos conhecidos.", "good");
  }
});
