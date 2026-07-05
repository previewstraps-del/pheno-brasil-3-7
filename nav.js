import { initializeApp, getApps } from "https://www.gstatic.com/firebasejs/10.12.0/firebase-app.js";

import {
  getAuth,
  createUserWithEmailAndPassword,
  signInWithEmailAndPassword,
  onAuthStateChanged,
  signOut,
  updateProfile,
  sendPasswordResetEmail,
  sendEmailVerification,
  GoogleAuthProvider,
  signInWithPopup
} from "https://www.gstatic.com/firebasejs/10.12.0/firebase-auth.js";

import {
  getFirestore,
  doc,
  setDoc,
  getDoc,
  serverTimestamp,
  collection,
  addDoc,
  deleteDoc
} from "https://www.gstatic.com/firebasejs/10.12.0/firebase-firestore.js";

/* =====================================================
   FIREBASE
===================================================== */

const firebaseConfig = {
  apiKey: "AIzaSyAJTlL-4piG67VOM_y480dhyib2qaF3Bso",
  authDomain: "phenobrasil.firebaseapp.com",
  projectId: "phenobrasil",
  storageBucket: "phenobrasil.firebasestorage.app",
  messagingSenderId: "825755980394",
  appId: "1:825755980394:web:caad888821d128fb133013"
};

const app = getApps().length ? getApps()[0] : initializeApp(firebaseConfig);

export const auth = getAuth(app);
export const db   = getFirestore(app);

const googleProvider = new GoogleAuthProvider();

/* =====================================================
   ADMINS — UIDs fixos (D6)
===================================================== */

const ADMIN_UIDS = [
  'nXQDSUS3gjQNZ40zM8g7N455Nyk2',
  'PyT60zd4APf2woeWvKsbKRsg77a2'
];

/* =====================================================
   HELPERS
===================================================== */

function safeElement(id) {
  return document.getElementById(id);
}

function updateCartBadges() {
  const total = JSON.parse(
    localStorage.getItem('pheno_cart') || '[]'
  ).reduce((sum, item) => sum + item.qty, 0);

  document.querySelectorAll('.cart-badge').forEach(badge => {
    badge.textContent = total;
    badge.classList.toggle('visible', total > 0);
  });
}

function showToast(message) {
  const toast = safeElement('toast');
  if (!toast) return;
  toast.textContent = message;
  toast.classList.add('show');
  setTimeout(() => toast.classList.remove('show'), 2200);
}

/* =====================================================
   DEVICE FINGERPRINT — D9
   Gera um ID único por dispositivo/navegador
===================================================== */

async function getDeviceId() {
  const raw = [
    navigator.userAgent,
    navigator.language,
    screen.width + 'x' + screen.height,
    screen.colorDepth,
    Intl.DateTimeFormat().resolvedOptions().timeZone,
    navigator.hardwareConcurrency
  ].join('|');

  const buf  = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(raw));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2,'0')).join('');
}

/* =====================================================
   2FA SESSION — D9
   Verifica se o dispositivo já autenticou nas últimas 24h
===================================================== */

async function verificar2FASession(uid) {
  try {
    const deviceId = await getDeviceId();
    const snap = await getDoc(doc(db, '2fa_sessions', uid));
    if (!snap.exists()) return false;

    const data = snap.data();
    if (data.deviceId !== deviceId) return false;

    const agora = Date.now();
    const expira = data.expiresAt?.toMillis?.() || 0;
    return agora < expira;
  } catch (_) {
    return false;
  }
}

async function salvar2FASession(uid) {
  try {
    const deviceId = await getDeviceId();
    const agora    = new Date();
    const expira   = new Date(agora.getTime() + 24 * 60 * 60 * 1000); // +24h

    await setDoc(doc(db, '2fa_sessions', uid), {
      deviceId,
      validatedAt: serverTimestamp(),
      expiresAt:   expira
    });
  } catch (_) {}
}

/* =====================================================
   2FA TOTP — D8 (Google Authenticator para usuários comuns)
   Valida o código TOTP usando a Cloud Function
===================================================== */

async function verificarTOTP(uid, code) {
  try {
    const resp = await fetch('https://us-central1-phenobrasil.cloudfunctions.net/verificarTOTP', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    // O servidor agora vai receber { data: { uid: "...", code: "..." } }
    body: JSON.stringify({ data: { uid, code } }) 
});
  const responseData = await resp.json();
        
        // Se a resposta vier dentro de um objeto { data: { valid: true } }
        // ou direto como { valid: true }, precisamos tratar:
        const valid = responseData.valid || (responseData.data && responseData.data.valid);
        return valid === true;

    } catch (err) {
        console.error('Erro na chamada fetch:', err);
        return false;
    }
}
async function obterQRCodeTOTP(uid, email) {
  try {
    const resp = await fetch('https://us-central1-phenobrasil.cloudfunctions.net/gerarTOTP', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ uid, email })
    });
    const data = await resp.json();
    return data; // { qrcode, secret, jaConfigurado }
  } catch (_) {
    return null;
  }
}

/* =====================================================
   2FA EMAIL — D7 (para admins, breeders, vendedores)
   Envia código via Cloud Function + Gmail SMTP
===================================================== */

async function enviarCodigo2FAEmail(uid, email) {
  try {
    const resp = await fetch('https://us-central1-phenobrasil.cloudfunctions.net/enviar2FAEmail', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ uid, email })
    });
    const data = await resp.json();
    return data.ok === true;
  } catch (_) {
    return false;
  }
}

async function verificarCodigo2FAEmail(uid, code) {
  try {
    const resp = await fetch('https://us-central1-phenobrasil.cloudfunctions.net/verificar2FAEmail', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ uid, code })
    });
    const data = await resp.json();
    return data.valid === true;
  } catch (_) {
    return false;
  }
}

/* =====================================================
   MODAL 2FA — UI
===================================================== */

function injetar2FAModal() {
  if (safeElement('modal-2fa')) return;

  document.body.insertAdjacentHTML('beforeend', `
    <div class="modal-overlay" id="modal-2fa" style="z-index:1000">
      <div class="modal" style="max-width:420px">
        <h2 id="2fa-titulo">Verificação em duas etapas</h2>
        <p class="modal-sub" id="2fa-sub"></p>

        <!-- TOTP: QR Code setup -->
        <div id="2fa-qr-wrap" style="display:none;text-align:center;margin:1rem 0">
          <p style="color:var(--muted);font-size:0.85rem;margin-bottom:0.8rem">
            Escaneie o QR Code com o Google Authenticator ou Authy:
          </p>
          <img id="2fa-qr-img" src="" alt="QR Code" style="width:200px;height:200px;border-radius:4px">
          <p style="color:var(--muted);font-size:0.78rem;margin-top:0.6rem">Após escanear, digite o código gerado abaixo.</p>
        </div>

        <div class="form-group" style="margin-top:1rem">
          <label>Código de verificação</label>
          <input type="text" id="2fa-code-input" placeholder="000000" maxlength="6"
            style="letter-spacing:0.3em;text-align:center;font-size:1.4rem;font-family:'Barlow Condensed'"
            oninput="this.value=this.value.replace(/[^0-9]/g,'')">
        </div>

        <div class="form-error" id="2fa-error"></div>

        <button class="form-submit" id="2fa-btn-confirmar" onclick="window._confirmar2FA()">Confirmar</button>

        <div id="2fa-reenviar-wrap" style="display:none;text-align:center;margin-top:0.8rem">
          <a id="2fa-reenviar-link" style="color:var(--muted);font-size:0.82rem;cursor:pointer" onclick="window._reenviar2FA()">
            Reenviar código por email
          </a>
          <span id="2fa-contador" style="display:none;color:var(--muted);font-size:0.82rem"></span>
        </div>

        <div id="2fa-backup-aviso" style="display:none;text-align:center;margin-top:0.8rem;padding:0.6rem;background:rgba(201,168,76,0.1);border:1px solid var(--gold);border-radius:4px">
          <p style="font-size:0.78rem;color:var(--gold);margin:0">⚠️ Ative o backup com email no Google Authenticator para não perder essa validação.</p>
        </div>

        <div id="2fa-perdeu-auth-wrap" style="display:none;text-align:center;margin-top:0.6rem">
          <a style="color:var(--muted);font-size:0.78rem;cursor:pointer" onclick="window.abrirResetAuthenticator()">Perdeu o Authenticator?</a>
        </div>

        <button class="modal-close" onclick="window._cancelar2FA()" style="top:1rem;right:1rem">✕</button>
      </div>
    </div>
  `);
}


/* =====================================================
   MODAL VERIFICAÇÃO DE EMAIL
===================================================== */

function injetarModalVerificacaoEmail() {
  if (safeElement('modal-verificar-email')) return;
  document.body.insertAdjacentHTML('beforeend', `
    <div class="modal-overlay" id="modal-verificar-email" style="z-index:1001">
      <div class="modal" style="max-width:420px;text-align:center">
        <h2>Verifique seu <span>Email</span></h2>
        <p class="modal-sub" style="margin-top:0.5rem">Enviamos um link de confirmação para <strong id="vem-email-display"></strong>. Acesse seu email e clique no link para continuar.</p>
        <p style="font-size:0.82rem;color:var(--muted);margin-top:1rem">Após confirmar, clique no botão abaixo.</p>
        <button class="form-submit" style="margin-top:1rem" onclick="window.verificarEmailConfirmado()">Já confirmei meu email</button>
        <div style="margin-top:1rem">
          <a id="vem-reenviar-link" style="color:var(--muted);font-size:0.82rem;cursor:pointer" onclick="window.reenviarVerificacaoEmail()">Reenviar email de verificação</a>
          <span id="vem-contador" style="display:none;color:var(--muted);font-size:0.82rem"></span>
        </div>
        <div class="form-error" id="vem-error" style="margin-top:0.5rem"></div>
        <div style="text-align:center;margin-top:1.2rem;padding-top:1rem;border-top:1px solid var(--border)">
          <a style="color:var(--muted);font-size:0.82rem;cursor:pointer" onclick="window.sairSemVerificar()">Não quero verificar agora — Sair</a>
        </div>
      </div>
    </div>
  `);
}

let _vemTimer = null;
function iniciarContadorVEM(segundos = 60) {
  const link     = safeElement('vem-reenviar-link');
  const contador = safeElement('vem-contador');
  if (!link || !contador) return;
  link.style.display     = 'none';
  contador.style.display = 'inline';
  let restante = segundos;
  contador.textContent = `Reenviar em ${restante}s`;
  if (_vemTimer) clearInterval(_vemTimer);
  _vemTimer = setInterval(() => {
    restante--;
    if (restante <= 0) {
      clearInterval(_vemTimer); _vemTimer = null;
      link.style.display     = 'inline';
      contador.style.display = 'none';
    } else {
      contador.textContent = `Reenviar em ${restante}s`;
    }
  }, 1000);
}

window.reenviarVerificacaoEmail = async () => {
  const link = safeElement('vem-reenviar-link');
  if (link && link.style.display === 'none') return;
  const user = auth.currentUser;
  if (!user) return;
  try {
    await sendEmailVerification(user);
    showToast('Email de verificação reenviado!');
    iniciarContadorVEM();
  } catch (_) {
    const errEl = safeElement('vem-error');
    if (errEl) errEl.textContent = 'Erro ao reenviar. Aguarde um momento.';
  }
};

window.sairSemVerificar = async () => {
  if (_vemTimer) { clearInterval(_vemTimer); _vemTimer = null; }
  safeElement('modal-verificar-email')?.classList.remove('open');
  document.body.style.overflow = '';
  try { await signOut(auth); } catch (_) {}
  location.reload();
};

window.verificarEmailConfirmado = async () => {
  const user = auth.currentUser;
  if (!user) return;
  await user.reload();
  if (user.emailVerified) {
    safeElement('modal-verificar-email')?.classList.remove('open');
    document.body.style.overflow = '';
    location.reload();
  } else {
    const errEl = safeElement('vem-error');
    if (errEl) errEl.textContent = 'Email ainda não confirmado. Verifique sua caixa de entrada.';
  }
};

async function mostrarModalVerificacaoEmail(user) {
  injetarModalVerificacaoEmail();
  const emailDisplay = safeElement('vem-email-display');
  if (emailDisplay) emailDisplay.textContent = user.email;
  try {
    await sendEmailVerification(user);
    iniciarContadorVEM();
  } catch (_) {}
  safeElement('modal-verificar-email')?.classList.add('open');
  document.body.style.overflow = 'hidden';
}

/* =====================================================
   MODAL ESQUECEU A SENHA
===================================================== */

function injetarModalEsqueceuSenha() {
  if (safeElement('modal-esqueceu-senha')) return;
  document.body.insertAdjacentHTML('beforeend', `
    <div class="modal-overlay" id="modal-esqueceu-senha" style="z-index:1001">
      <div class="modal" style="max-width:400px">
        <button class="modal-close" onclick="window.fecharEsqueceuSenha()">✕</button>
        <h2>Redefinir <span>Senha</span></h2>
        <p class="modal-sub">Digite seu email e enviaremos um link para redefinir sua senha.</p>
        <div class="form-group" style="margin-top:1rem">
          <label>Email</label>
          <input type="email" id="reset-senha-email" placeholder="seu@email.com">
        </div>
        <div class="form-error" id="reset-senha-error"></div>
        <button class="form-submit" style="margin-top:1rem" onclick="window.enviarResetSenha()">Enviar link</button>
        <div style="text-align:center;margin-top:0.8rem">
          <a id="reset-senha-reenviar-link" style="display:none;color:var(--muted);font-size:0.82rem;cursor:pointer" onclick="window.enviarResetSenha()">Reenviar link</a>
          <span id="reset-senha-contador" style="display:none;color:var(--muted);font-size:0.82rem"></span>
        </div>
      </div>
    </div>
  `);
}

let _resetSenhaTimer = null;
function iniciarContadorResetSenha(segundos = 60) {
  const link     = safeElement('reset-senha-reenviar-link');
  const contador = safeElement('reset-senha-contador');
  if (!link || !contador) return;
  link.style.display     = 'none';
  contador.style.display = 'inline';
  let restante = segundos;
  contador.textContent = `Reenviar em ${restante}s`;
  if (_resetSenhaTimer) clearInterval(_resetSenhaTimer);
  _resetSenhaTimer = setInterval(() => {
    restante--;
    if (restante <= 0) {
      clearInterval(_resetSenhaTimer); _resetSenhaTimer = null;
      link.style.display     = 'inline';
      contador.style.display = 'none';
    } else {
      contador.textContent = `Reenviar em ${restante}s`;
    }
  }, 1000);
}

window.abrirEsqueceuSenha = () => {
  closeModal();
  injetarModalEsqueceuSenha();
  safeElement('reset-senha-email').value    = '';
  const errEl = safeElement('reset-senha-error');
  if (errEl) errEl.textContent = '';
  safeElement('modal-esqueceu-senha')?.classList.add('open');
  document.body.style.overflow = 'hidden';
};

window.fecharEsqueceuSenha = () => {
  safeElement('modal-esqueceu-senha')?.classList.remove('open');
  document.body.style.overflow = '';
};

window.enviarResetSenha = async () => {
  const email = safeElement('reset-senha-email')?.value.trim();
  const errEl = safeElement('reset-senha-error');
  const link  = safeElement('reset-senha-reenviar-link');
  if (!email) { if (errEl) errEl.textContent = 'Digite seu email.'; return; }
  if (link && link.style.display === 'none') return; // bloqueado pelo contador
  try {
    await sendPasswordResetEmail(auth, email);
    if (errEl) errEl.textContent = '';
    showToast('Link enviado! Verifique seu email.');
    // Mostrar reenviar com contador
    if (link) link.style.display = 'inline';
    iniciarContadorResetSenha();
  } catch (e) {
    const msgs = {
      'auth/user-not-found': 'Email não encontrado.',
      'auth/invalid-email':  'Email inválido.'
    };
    if (errEl) errEl.textContent = msgs[e.code] || 'Erro ao enviar. Tente novamente.';
  }
};

/* =====================================================
   MODAL RESET DO AUTHENTICATOR
===================================================== */

function injetarModalResetAuthenticator() {
  if (safeElement('modal-reset-auth')) return;
  document.body.insertAdjacentHTML('beforeend', `
    <div class="modal-overlay" id="modal-reset-auth" style="z-index:1001">
      <div class="modal" style="max-width:420px">
        <button class="modal-close" onclick="window.fecharResetAuthenticator()">✕</button>
        <h2>Recuperar <span>Authenticator</span></h2>
        <div id="reset-auth-step1">
          <p class="modal-sub">Digite seu email para receber um link de recuperação do Authenticator.</p>
          <div class="form-group" style="margin-top:1rem">
            <label>Email</label>
            <input type="email" id="reset-auth-email" placeholder="seu@email.com">
          </div>
          <div class="form-error" id="reset-auth-error"></div>
          <button class="form-submit" style="margin-top:1rem" onclick="window.enviarResetAuthenticator()">Enviar link de recuperação</button>
          <div style="text-align:center;margin-top:0.8rem">
            <a id="reset-auth-reenviar-link" style="display:none;color:var(--muted);font-size:0.82rem;cursor:pointer" onclick="window.enviarResetAuthenticator()">Reenviar link</a>
            <span id="reset-auth-contador" style="display:none;color:var(--muted);font-size:0.82rem"></span>
          </div>
        </div>
        <div id="reset-auth-step2" style="display:none;text-align:center">
          <p class="modal-sub">✅ Link enviado! Verifique seu email e clique no link para desvincular o Authenticator.</p>
          <p style="font-size:0.82rem;color:var(--muted);margin-top:0.5rem">Após clicar no link, faça login novamente e configure um novo Authenticator.</p>
        </div>
      </div>
    </div>
  `);
}

let _resetAuthTimer = null;
function iniciarContadorResetAuth(segundos = 60) {
  const link     = safeElement('reset-auth-reenviar-link');
  const contador = safeElement('reset-auth-contador');
  if (!link || !contador) return;
  link.style.display     = 'none';
  contador.style.display = 'inline';
  let restante = segundos;
  contador.textContent = `Reenviar em ${restante}s`;
  if (_resetAuthTimer) clearInterval(_resetAuthTimer);
  _resetAuthTimer = setInterval(() => {
    restante--;
    if (restante <= 0) {
      clearInterval(_resetAuthTimer); _resetAuthTimer = null;
      link.style.display     = 'inline';
      contador.style.display = 'none';
    } else {
      contador.textContent = `Reenviar em ${restante}s`;
    }
  }, 1000);
}

window.abrirResetAuthenticator = () => {
  closeModal();
  fechar2FAModal();
  injetarModalResetAuthenticator();
  safeElement('reset-auth-step1').style.display = 'block';
  safeElement('reset-auth-step2').style.display = 'none';
  const errEl = safeElement('reset-auth-error');
  if (errEl) errEl.textContent = '';
  safeElement('modal-reset-auth')?.classList.add('open');
  document.body.style.overflow = 'hidden';
};

window.fecharResetAuthenticator = () => {
  safeElement('modal-reset-auth')?.classList.remove('open');
  document.body.style.overflow = '';
};

window.enviarResetAuthenticator = async () => {
  const email = safeElement('reset-auth-email')?.value.trim();
  const errEl = safeElement('reset-auth-error');
  const link  = safeElement('reset-auth-reenviar-link');
  if (!email) { if (errEl) errEl.textContent = 'Digite seu email.'; return; }
  if (link && link.style.display === 'none') return; // bloqueado pelo contador
  try {
    const resp = await fetch('https://us-central1-phenobrasil.cloudfunctions.net/resetAuthenticator', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email })
    });
    const data = await resp.json();
    if (data.ok) {
      safeElement('reset-auth-step1').style.display = 'none';
      safeElement('reset-auth-step2').style.display = 'block';
      if (link) link.style.display = 'inline';
      iniciarContadorResetAuth();
    } else {
      if (errEl) errEl.textContent = data.error || 'Erro ao enviar. Tente novamente.';
    }
  } catch (_) {
    if (errEl) errEl.textContent = 'Erro de conexão. Tente novamente.';
  }
};

/* =====================================================
   FLUXO 2FA — orquestra o processo por role
===================================================== */

let _2fa_resolve = null;
let _2fa_uid     = null;
let _2fa_email   = null;
let _2fa_tipo    = null; // 'email' | 'totp'

async function iniciar2FA(uid, email, roles) {
  injetar2FAModal();

  const isElevado = ADMIN_UIDS.includes(uid) ||
    roles.includes('breeder') ||
    roles.includes('vendedor');

  _2fa_uid   = uid;
  _2fa_email = email;
  _2fa_tipo  = isElevado ? 'email' : 'totp';

  const modal  = safeElement('modal-2fa');
  const titulo = safeElement('2fa-titulo');
  const sub    = safeElement('2fa-sub');
  const qrWrap = safeElement('2fa-qr-wrap');
  const input  = safeElement('2fa-code-input');
  const errEl  = safeElement('2fa-error');
  const reenv  = safeElement('2fa-reenviar-wrap');

  if (errEl) errEl.textContent = '';
  if (input) input.value = '';

  if (_2fa_tipo === 'email') {
    titulo.textContent = 'Verificação por Email';
    sub.textContent    = `Enviamos um código para ${email}. Verifique sua caixa de entrada.`;
    if (qrWrap) qrWrap.style.display = 'none';
    if (reenv)  reenv.style.display  = 'block';

    // Checa se já existe código válido e ainda dentro dos 60s
    try {
      const codeSnap = await getDoc(doc(db, '2fa_codes', uid));
      if (codeSnap.exists()) {
        const codeData  = codeSnap.data();
        const enviadoEm = codeData.criadoEm?.toMillis?.() || 0;
        const agora     = Date.now();
        const restante  = Math.ceil(60 - (agora - enviadoEm) / 1000);
        if (restante > 0) {
          // Código ainda válido — não reenviar, mostrar contador com tempo restante
          sub.textContent = `Já enviamos um código para ${email}. Verifique sua caixa de entrada.`;
          setTimeout(() => iniciarContador2FA(restante), 100);
        } else {
          // Expirou — reenviar
          await enviarCodigo2FAEmail(uid, email);
          setTimeout(() => iniciarContador2FA(), 100);
        }
      } else {
        // Nunca enviou — enviar agora
        await enviarCodigo2FAEmail(uid, email);
        setTimeout(() => iniciarContador2FA(), 100);
      }
    } catch (_) {
      await enviarCodigo2FAEmail(uid, email);
      setTimeout(() => iniciarContador2FA(), 100);
    }
  } else {
    // TOTP
    titulo.textContent = 'Google Authenticator';
    if (reenv) reenv.style.display = 'none';

    // Mostrar aviso de backup e link "Perdeu o Authenticator?"
    const backupAviso  = safeElement('2fa-backup-aviso');
    const perdeuWrap   = safeElement('2fa-perdeu-auth-wrap');
    if (backupAviso) backupAviso.style.display = 'block';
    if (perdeuWrap)  perdeuWrap.style.display  = 'block';

    const totp = await obterQRCodeTOTP(uid, email);
    if (totp && !totp.jaConfigurado) {
      // Primeira vez — mostra QR
      sub.textContent = 'Configure o Google Authenticator escaneando o QR Code abaixo.';
      if (qrWrap) qrWrap.style.display = 'block';
      const qrImg = safeElement('2fa-qr-img');
      if (qrImg) qrImg.src = totp.qrcode;
    } else {
      sub.textContent = 'Digite o código gerado pelo Google Authenticator.';
      if (qrWrap) qrWrap.style.display = 'none';
    }
  }

  modal.classList.add('open');
  document.body.style.overflow = 'hidden';
  setTimeout(() => input?.focus(), 300);

  return new Promise(resolve => { _2fa_resolve = resolve; });
}

window._confirmar2FA = async () => {
  const input  = safeElement('2fa-code-input');
  const errEl  = safeElement('2fa-error');
  const btn    = safeElement('2fa-btn-confirmar');
  const code   = input?.value.trim();

  if (!code || code.length < 6) {
    if (errEl) errEl.textContent = 'Digite o código de 6 dígitos.';
    return;
  }

  if (btn) { btn.disabled = true; btn.textContent = 'Verificando...'; }
  if (errEl) errEl.textContent = '';

  let valido = false;
  if (_2fa_tipo === 'email') {
    valido = await verificarCodigo2FAEmail(_2fa_uid, code);
  } else {
    valido = await verificarTOTP(_2fa_uid, code);
  }

  if (valido) {
    await salvar2FASession(_2fa_uid);
    fechar2FAModal();
    
    // --- ADIÇÃO NECESSÁRIA ---
    // Força o recarregamento da página para atualizar o estado do Auth e da Nav
    location.reload(); 
    // -------------------------
    
    if (_2fa_resolve) _2fa_resolve(true);
  } else {
    if (errEl) errEl.textContent = 'Código inválido ou expirado. Tente novamente.';
    if (btn) { btn.disabled = false; btn.textContent = 'Confirmar'; }
  }
};

let _reenviarTimer = null;

function iniciarContador2FA(segundos = 60) {
  const link     = safeElement('2fa-reenviar-link');
  const contador = safeElement('2fa-contador');
  if (!link || !contador) return;

  link.style.display    = 'none';
  contador.style.display = 'inline';

  let restante = segundos;
  contador.textContent = `Reenviar em ${restante}s`;

  if (_reenviarTimer) clearInterval(_reenviarTimer);
  _reenviarTimer = setInterval(() => {
    restante--;
    if (restante <= 0) {
      clearInterval(_reenviarTimer);
      _reenviarTimer = null;
      link.style.display    = 'inline';
      contador.style.display = 'none';
    } else {
      contador.textContent = `Reenviar em ${restante}s`;
    }
  }, 1000);
}

window._reenviar2FA = async () => {
  if (!_2fa_uid || !_2fa_email) return;
  const link = safeElement('2fa-reenviar-link');
  if (link && link.style.display === 'none') return; // bloqueado pelo contador
  const errEl = safeElement('2fa-error');
  if (errEl) errEl.textContent = '';
  const ok = await enviarCodigo2FAEmail(_2fa_uid, _2fa_email);
  if (ok) { showToast('Código reenviado!'); iniciarContador2FA(); }
  else if (errEl) errEl.textContent = 'Erro ao reenviar. Tente novamente.';
};

window._cancelar2FA = async () => {
  fechar2FAModal();
  if (_2fa_resolve) _2fa_resolve(false);
  try { await signOut(auth); } catch (_) {}
  location.reload();
};

function fechar2FAModal() {
  const modal = safeElement('modal-2fa');
  if (modal) modal.classList.remove('open');
  document.body.style.overflow = '';
  _2fa_resolve = null;
  _2fa_uid     = null;
  _2fa_email   = null;
  _2fa_tipo    = null;
}

/* =====================================================
   GLOBAL
===================================================== */

window.mostrarBreeders = (event) => {
  event.preventDefault();
  const path = window.location.pathname;
  if (path.endsWith("index.html") || path === "/" || path === "/index.html") {
    alert("Abrindo seletor de Breeders!");
  } else {
    location.href = 'breeders.html';
  }
};

/* =====================================================
   NAV
===================================================== */

export function renderNav(activeLink = '') {

  const links = [
    { label: 'Inicio', href: 'index.html' },
    { label: 'Breeders', href: 'breeders.html' },
    {
      label: 'Colecionaveis',
      href: 'sementes.html',
      dropdown: [
        {
          icon: '🌿',
          label: 'Breeders',
          sub: 'Conheça quem cultiva',
          href: 'breeders.html',
          onclick: 'window.mostrarBreeders(event)'
        },
        {
          icon: '🧬',
          label: 'Tipos de Sementes',
          sub: 'Fem, Auto, Regular...',
          href: '#'
        },
        {
          icon: '🔬',
          label: 'Canabinoides',
          sub: 'THC, CBD e mais',
          href: '#'
        }
      ]
    },
    { label: 'Sobre', href: 'sobre.html' },
    { label: 'Contato', href: 'contato.html' },
    { label: 'Loja', href: 'loja.html' },
    { label: 'Revista', href: 'Revista.html' },
    { label: 'cursos e mentorias', href: 'cursos.html' }
  ];

  const navItems = links.map(link => {
    const active = activeLink === link.label ? 'active' : '';

    if (link.dropdown) {
      const dropdownItems = link.dropdown.map(item => {
        const dropOnclick = item.onclick ? `onclick="${item.onclick}"` : '';
        return `
          <a href="${item.href}" ${dropOnclick}>
            ${item.icon} ${item.label}
            <span class="dropdown-sub">${item.sub}</span>
          </a>
        `;
      }).join('');

      return `
        <li>
          <a href="${link.href}" class="${active}">
            ${link.label}
            <span class="arrow">▼</span>
          </a>
          <div class="dropdown">
            ${dropdownItems}
          </div>
        </li>
      `;
    }

    return `
      <li>
        <a href="${link.href}" class="${active}">
          ${link.label}
        </a>
      </li>
    `;
  }).join('');

  document.body.insertAdjacentHTML(
    'afterbegin',
    `
    <div class="topbar">
      <span>🌱 Sementes premium de coleção — Breeders brasileiros</span>
      <div id="auth-top-links"></div>
    </div>

    <nav>
      <div class="nav-logo" onclick="location.href='index.html'">
        <h2>PHENO<span style="color:var(--gold)">BRASIL</span></h2>
      </div>

      <ul class="nav-center" id="nav-center">
        ${navItems}
      </ul>

      <div class="nav-right" id="auth-nav-btn"></div>
    </nav>

    <!-- MODAL LOGIN/REGISTER -->
    <div class="modal-overlay" id="modal-overlay" onclick="closeModalOutside(event)">
      <div class="modal">
        <button class="modal-close" onclick="closeModal()">✕</button>

        <h2>Bem-vindo à <span>Pheno<span style="color:var(--gold)">Brasil</span></span></h2>
        <p class="modal-sub">Acesse sua conta ou crie uma nova</p>

        <div class="modal-tabs">
          <button class="modal-tab active" id="tab-login" onclick="switchTab('login')">Entrar</button>
          <button class="modal-tab" id="tab-register" onclick="switchTab('register')">Cadastrar</button>
        </div>

        <!-- LOGIN PANEL -->
        <div class="form-panel active" id="panel-login">
          <button class="btn-google" onclick="doGoogleLogin()">
            <img src="https://www.google.com/favicon.ico" alt="Google"> Entrar com Google
          </button>

          <div class="form-divider"><span>ou com email</span></div>

          <div class="form-group">
            <label>Email</label>
            <input type="email" id="login-email" placeholder="seu@email.com">
          </div>

          <div class="form-group">
            <label>Senha</label>
            <input type="password" id="login-password" placeholder="••••••••">
          </div>

          <div class="form-error" id="login-error"></div>

          <button class="form-submit" id="login-btn" onclick="doLogin()">Entrar</button>

          <div style="text-align:center;margin-top:0.8rem;display:flex;flex-direction:column;gap:0.4rem">
            <a style="color:var(--muted);font-size:0.82rem;cursor:pointer" onclick="window.abrirEsqueceuSenha()">Esqueceu a senha?</a>
            <a style="color:var(--muted);font-size:0.82rem;cursor:pointer" onclick="window.abrirResetAuthenticator()">Perdeu o Authenticator?</a>
          </div>
          <div class="form-divider" style="margin-top:1rem;">
            <span>Não tem conta? <a class="switch-link" onclick="switchTab('register')">Cadastre-se</a></span>
          </div>
        </div>

        <!-- REGISTER PANEL -->
        <div class="form-panel" id="panel-register">
          <button class="btn-google" onclick="doGoogleLogin()">
            <img src="https://www.google.com/favicon.ico" alt="Google"> Cadastrar com Google
          </button>

          <div class="form-divider"><span>ou com email</span></div>

          <div class="form-group">
            <label>Nome completo</label>
            <input type="text" id="reg-name" placeholder="Seu nome">
          </div>

          <div class="form-group">
            <label>Email</label>
            <input type="email" id="reg-email" placeholder="seu@email.com">
          </div>

          <div class="form-group">
            <label>Telefone / WhatsApp</label>
            <input type="tel" id="reg-phone" placeholder="(51) 99999-9999">
          </div>

          <div class="form-group">
            <label>Senha</label>
            <input type="password" id="reg-password" placeholder="Mínimo 6 caracteres">
          </div>

          <div class="form-group">
            <label>Confirmar Senha</label>
            <input type="password" id="reg-confirm" placeholder="Repita a senha">
          </div>

          <div class="form-error" id="reg-error"></div>

          <button class="form-submit" id="reg-btn" onclick="doRegister()">Criar conta</button>

          <div class="form-divider" style="margin-top:1rem;">
            <span>Já tem conta? <a class="switch-link" onclick="switchTab('login')">Entrar</a></span>
          </div>
        </div>
      </div>
    </div>

    <!-- CARRINHO -->
    <div class="cart-backdrop" id="cart-backdrop" onclick="fecharCarrinho()"></div>

    <div class="cart-drawer" id="cart-drawer">
      <div class="cart-header">
        <h3>🛒 Seu Carrinho</h3>
        <button class="cart-close-btn" onclick="fecharCarrinho()">✕</button>
      </div>

      <div class="cart-items" id="cart-items"></div>

      <div class="cart-footer" id="cart-footer" style="display:none">
        <div class="cart-total-row">
          <span class="cart-total-label">Total</span>
          <span class="cart-total-value" id="cart-total">R$ 0,00</span>
        </div>

        <button class="checkout-btn" onclick="finalizarPedido()">
          Finalizar Pedido
        </button>

        <button class="clear-cart-btn" onclick="limparCarrinho()">
          Esvaziar carrinho
        </button>
      </div>
    </div>

    <div class="toast" id="toast"></div>
    `
  );
}

/* =====================================================
   MODAL FUNCTIONS
===================================================== */

function openModal(tab) {
  document.getElementById('modal-overlay').classList.add('open');
  switchTab(tab || 'login');
  document.body.style.overflow = 'hidden';
}

function closeModal() {
  document.getElementById('modal-overlay').classList.remove('open');
  document.body.style.overflow = '';
}

function closeModalOutside(e) {
  if (e.target === document.getElementById('modal-overlay')) closeModal();
}

function switchTab(tab) {
  document.querySelectorAll('.modal-tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.form-panel').forEach(p => p.classList.remove('active'));
  document.getElementById('tab-' + tab).classList.add('active');
  document.getElementById('panel-' + tab).classList.add('active');
  document.getElementById('login-error').textContent = '';
  document.getElementById('reg-error').textContent = '';
}

document.addEventListener('keydown', e => {
  if (e.key === 'Escape') closeModal();
});

/* =====================================================
   AUTHENTICATION FUNCTIONS
===================================================== */

async function doGoogleLogin() {
  try {
    const result = await signInWithPopup(auth, googleProvider);
    const user   = result.user;

    // Garante registro na coleção users
    const userRef = doc(db, 'users', user.uid);
    const snap    = await getDoc(userRef);
    if (!snap.exists()) {
      await setDoc(userRef, {
        nome:     user.displayName || '',
        email:    user.email,
        telefone: '',
        photo:    user.photoURL || '',
        criadoEm: serverTimestamp(),
        metodo:   'google',
        roles:    []
      });
    }

    closeModal();
    // 2FA será tratado pelo onAuthStateChanged
  } catch(e) {
    if (e.code !== 'auth/popup-closed-by-user') {
      showToast('Erro ao entrar com Google. Tente novamente.');
    }
  }
}

async function doLogin() {
  const email    = document.getElementById('login-email').value.trim();
  const password = document.getElementById('login-password').value;
  const errEl    = document.getElementById('login-error');
  const btn      = document.getElementById('login-btn');

  if (!email || !password) { errEl.textContent = 'Preencha todos os campos.'; return; }

  errEl.textContent = '';
  btn.disabled = true;
  btn.textContent = 'Entrando...';

  try {
    await signInWithEmailAndPassword(auth, email, password);
    closeModal();
    // 2FA será tratado pelo onAuthStateChanged
  } catch(e) {
    const msgs = {
      'auth/user-not-found':    'Email não encontrado.',
      'auth/wrong-password':    'Senha incorreta.',
      'auth/invalid-credential':'Email ou senha incorretos.',
      'auth/too-many-requests': 'Muitas tentativas. Tente mais tarde.'
    };
    errEl.textContent = msgs[e.code] || 'Erro ao entrar.';
  } finally {
    btn.disabled = false;
    btn.textContent = 'Entrar';
  }
}

async function doRegister() {
  const name     = document.getElementById('reg-name').value.trim();
  const email    = document.getElementById('reg-email').value.trim();
  const phone    = document.getElementById('reg-phone').value.trim();
  const password = document.getElementById('reg-password').value;
  const confirm  = document.getElementById('reg-confirm').value;
  const errEl    = document.getElementById('reg-error');
  const btn      = document.getElementById('reg-btn');

  if (!name || !email || !phone || !password || !confirm) {
    errEl.textContent = 'Preencha todos os campos.'; return;
  }
  if (password !== confirm) { errEl.textContent = 'As senhas não coincidem.'; return; }
  if (password.length < 6)  { errEl.textContent = 'Senha deve ter pelo menos 6 caracteres.'; return; }

  errEl.textContent = '';
  btn.disabled = true;
  btn.textContent = 'Criando conta...';

  try {
    const cred = await createUserWithEmailAndPassword(auth, email, password);
    await updateProfile(cred.user, { displayName: name });

    await setDoc(doc(db, 'users', cred.user.uid), {
      nome:     name,
      email,
      telefone: phone,
      criadoEm: serverTimestamp(),
      metodo:   'email',
      roles:    []
    });

    await sendEmailVerification(cred.user);
    closeModal();
    showToast('✓ Conta criada! Confirme seu email para continuar.');
  } catch(e) {
    const msgs = {
      'auth/email-already-in-use': 'Este email já está cadastrado.',
      'auth/invalid-email':        'Email inválido.',
      'auth/weak-password':        'Senha muito fraca.'
    };
    errEl.textContent = msgs[e.code] || 'Erro ao cadastrar.';
  } finally {
    btn.disabled = false;
    btn.textContent = 'Criar conta';
  }
}

async function fazerLogout() {
  try {
    await signOut(auth);
    location.reload();
  } catch (_) {}
}

window.openModal         = openModal;
window.closeModal        = closeModal;
window.closeModalOutside = closeModalOutside;
window.switchTab         = switchTab;
window.doGoogleLogin     = doGoogleLogin;
window.doLogin           = doLogin;
window.doRegister        = doRegister;
window.fazerLogout       = fazerLogout;

/* =====================================================
   CART
===================================================== */

export function initCarrinho() {

  let carrinho = JSON.parse(localStorage.getItem('pheno_cart') || '[]');

  const salvar = () => localStorage.setItem('pheno_cart', JSON.stringify(carrinho));

  const render = () => {
    const container = safeElement('cart-items');
    const footer    = safeElement('cart-footer');
    if (!container || !footer) return;

    if (!carrinho.length) {
      container.innerHTML = `
        <div class="cart-empty">
          <div class="cart-empty-icon">🛒</div>
          <p>Carrinho vazio.<br>Adicione produtos para começar seu pedido!</p>
        </div>`;
      footer.style.display = 'none';
      return;
    }

    let total = 0;
    container.innerHTML = '';

    carrinho.forEach((item, idx) => {
      total += item.price * item.qty;
      const div = document.createElement('div');
      div.className = 'cart-item';
      div.innerHTML = `
        <img class="cart-item-img" src="${item.image || ''}" alt="${item.name}">
        <div>
          <div class="cart-item-name">${item.name}</div>
          <div class="cart-item-sub">${item.type}</div>
          <div class="cart-item-price">R$ ${(item.price * item.qty).toFixed(2).replace('.', ',')}</div>
        </div>
        <div class="cart-item-controls">
          <div class="qty-controls">
            <button class="qty-btn" onclick="mudarQty(${idx},-1)">−</button>
            <span class="qty-num">${item.qty}</span>
            <button class="qty-btn" onclick="mudarQty(${idx},1)">+</button>
          </div>
          <button class="remove-btn" onclick="removerItem(${idx})">remover</button>
        </div>`;
      container.appendChild(div);
    });

    const totalEl = safeElement('cart-total');
    if (totalEl) totalEl.textContent = 'R$ ' + total.toFixed(2).replace('.', ',');
    footer.style.display = 'block';
    updateCartBadges();
  };

  window.abrirCarrinho = () => {
    render();
    safeElement('cart-drawer')?.classList.add('open');
    safeElement('cart-backdrop')?.classList.add('open');
  };

  window.fecharCarrinho = () => {
    safeElement('cart-drawer')?.classList.remove('open');
    safeElement('cart-backdrop')?.classList.remove('open');
  };

  window.mudarQty = (idx, delta) => {
    carrinho[idx].qty += delta;
    if (carrinho[idx].qty <= 0) carrinho.splice(idx, 1);
    salvar(); render(); updateCartBadges();
  };

  window.removerItem = (idx) => {
    const nome = carrinho[idx].name;
    carrinho.splice(idx, 1);
    salvar(); render(); updateCartBadges();
    showToast(`${nome} removido`);
  };

  window.limparCarrinho = () => {
    carrinho = []; salvar(); render(); updateCartBadges();
  };

  window.finalizarPedido = () => {
    if (!carrinho.length) return;
    window.fecharCarrinho();
    location.href = 'checkout.html';
  };

  window.adicionarAoCarrinho = (id, name, type, price, image) => {
    const existing = carrinho.findIndex(item => item.id === id);
    if (existing > -1) {
      carrinho[existing].qty++;
      showToast(`+1 ${name} adicionado! ✅`);
    } else {
      carrinho.push({ id, name, type, price, image, qty: 1 });
      showToast(`✅ ${name} adicionado!`);
    }
    salvar();
    updateCartBadges();

    const button = document.querySelector(`[data-product-id="${id}"]`);
    if (button) {
      button.textContent = '✓ Adicionado';
      button.classList.add('added');
      setTimeout(() => {
        button.textContent = '+ Carrinho';
        button.classList.remove('added');
      }, 1500);
    }
  };

  updateCartBadges();
}

/* =====================================================
   AUTH STATE & UI — D4, D6, D7, D8, D9
===================================================== */

export function initAuth() {

  // Retorna array de roles do usuário
  const getRoles = (userData) => {
    if (userData?.roles && Array.isArray(userData.roles)) return userData.roles;
    if (userData?.role) return [userData.role];
    return [];
  };

  // Monta botões da nav conforme roles — D4
  const buildLogged = (user, roles) => {
    const name  = (user.displayName || user.email.split('@')[0]).split(' ')[0];
    const photo = user.photoURL || '';

    const isAdmin   = ADMIN_UIDS.includes(user.uid);
    const isBreeder = roles.includes('breeder');
    const isVendedor= roles.includes('vendedor');
    const isPainel  = isAdmin || isBreeder || isVendedor;

    let painelBtn = '';
    if (isAdmin) {
      painelBtn = `<button class="nav-btn primary" style="background:var(--red);border-color:var(--red)" onclick="location.href='admin.html'">⚙️ Admin</button>`;
    } else if (isPainel) {
      painelBtn = `<button class="nav-btn primary" onclick="location.href='dashboard.html'">Meu Painel</button>`;
    }

    return `
      <div id="user-display" style="display:flex;align-items:center;gap:0.5rem;color:var(--gold);">
        ${photo ? `<img src="${photo}" alt="" style="width:28px;height:28px;border-radius:50%;object-fit:cover;">` : '👤'} ${name}
      </div>
      ${painelBtn}
      ${!isPainel ? `<button class="nav-btn primary" onclick="location.href='meu_perfil.html'">Meu Perfil</button>` : ''}
      <button class="nav-btn" onclick="fazerLogout()">Sair</button>
      <button class="cart-nav-btn" onclick="abrirCarrinho()">
        🛒 <span class="cart-badge"></span>
      </button>
    `;
  };

  const buildGuest = () => `
    <button class="nav-btn" onclick="openModal('login')">Entrar</button>
    <button class="nav-btn primary" onclick="openModal('register')">Cadastrar</button>
    <button class="cart-nav-btn" onclick="abrirCarrinho()">
      🛒 <span class="cart-badge"></span>
    </button>
  `;

  onAuthStateChanged(auth, async (user) => {
    const topLinks = safeElement('auth-top-links');
    const navBtn   = safeElement('auth-nav-btn');

    if (user) {
      // Busca dados do usuário
      let userData = null;
      try {
        const snap = await getDoc(doc(db, 'users', user.uid));
        if (snap.exists()) userData = snap.data();
      } catch (_) {}

      // Fallback para coleção legada
      if (!userData) {
        try {
          const snap = await getDoc(doc(db, 'usuarios', user.uid));
          if (snap.exists()) userData = snap.data();
        } catch (_) {}
      }

      const roles   = getRoles(userData);
      const isAdmin = ADMIN_UIDS.includes(user.uid);

      // ── VERIFICAÇÃO DE EMAIL ────────────────────────────
      // Google login já vem verificado; admins são isentos
      // Para qualquer outro usuário sem email verificado, exige confirmação
      if (!user.emailVerified && !isAdmin) {
        if (navBtn) navBtn.innerHTML = `<span style="color:var(--muted);font-size:0.85rem">Aguardando verificação...</span>`;
        await mostrarModalVerificacaoEmail(user);
        return;
      }
      // ───────────────────────────────────────────────────

      // ── 2FA — D7, D8, D9 ──────────────────────────────
      // Elevados (admin/breeder/vendedor) sempre passam pelo 2FA por email
      // Usuários comuns só passam pelo 2FA TOTP se já tiverem TOTP configurado
      const isElevado = isAdmin || roles.includes('breeder') || roles.includes('vendedor');
      // Elevados: 2FA por email sempre
      // Usuários comuns: TOTP sempre (configurar na primeira vez, validar nas seguintes)
      const precisa2FA = true;

      if (precisa2FA) {
        const sessionValida = await verificar2FASession(user.uid);
        if (!sessionValida) {
          // Bloqueia UI enquanto 2FA não for validado
          if (navBtn) navBtn.innerHTML = `<span style="color:var(--muted);font-size:0.85rem">Verificando...</span>`;

          const ok = await iniciar2FA(user.uid, user.email, roles);
          if (!ok) {
            // Usuário cancelou — faz logout
            await signOut(auth);
            if (navBtn) navBtn.innerHTML = buildGuest();
            if (topLinks) topLinks.innerHTML = `<a onclick="openModal('login')" style="cursor:pointer;">Entrar / Login</a>`;
            updateCartBadges();
            return;
          }
        }
      }
      // ──────────────────────────────────────────────────

      if (topLinks) {
        topLinks.innerHTML = `<span style="color:var(--gold)">Conectado: ${user.email}</span>`;
      }

      if (navBtn) {
        navBtn.innerHTML = buildLogged(user, roles);
      }

    } else {
      if (topLinks) {
        topLinks.innerHTML = `<a onclick="openModal('login')" style="cursor:pointer;">Entrar / Login</a>`;
      }
      if (navBtn) {
        navBtn.innerHTML = buildGuest();
      }
    }

    updateCartBadges();
  });
}