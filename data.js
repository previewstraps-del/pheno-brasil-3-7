import { db } from './nav.js';
import {
  collection, getDocs, getDoc,
  query, where, doc
} from "https://www.gstatic.com/firebasejs/10.12.0/firebase-firestore.js";

// ── BREEDERS ─────────────────────────────────────────────
// Retorna todos os breeders com contagem de strains
export async function getBreeders() {
  const [breedersSnap, prodsSnap] = await Promise.all([
    getDocs(query(collection(db, "users"), where("role", "==", "breeder"))),
    getDocs(collection(db, "products"))
  ]);

  const contagem = {};
  prodsSnap.forEach(d => {
    const uid = d.data().breederUid;
    if (uid) contagem[uid] = (contagem[uid] || 0) + 1;
  });

  return breedersSnap.docs.map(d => ({
    id:     d.id,
    ...d.data(),
    totalStrains: contagem[d.id] || 0,
    avatar: d.data().photo ||
      `https://ui-avatars.com/api/?name=${encodeURIComponent(d.data().name || 'B')}&background=3a7d44&color=fff&size=160`
  }));
}

// Retorna um breeder pelo uid + suas strains
export async function getBreederComStrains(uid) {
  const [userSnap, prodsSnap] = await Promise.all([
    getDoc(doc(db, "users", uid)),
    getDocs(query(collection(db, "products"), where("breederUid", "==", uid)))
  ]);

  const breeder = userSnap.exists() ? { id: userSnap.id, ...userSnap.data() } : null;
  if (breeder) {
    breeder.avatar = breeder.photo ||
      `https://ui-avatars.com/api/?name=${encodeURIComponent(breeder.name || 'B')}&background=3a7d44&color=fff&size=128`;
  }

  const strains = prodsSnap.docs.map(d => ({ id: d.id, ...d.data() }));
  return { breeder, strains };
}

// ── SEMENTES (STRAINS) ────────────────────────────────────
// Retorna todas as strains
export async function getStrains() {
  const snap = await getDocs(collection(db, "products"));
  return snap.docs.map(d => ({ id: d.id, ...d.data() }));
}

// Retorna uma strain pelo id
export async function getStrain(id) {
  const snap = await getDoc(doc(db, "products", id));
  return snap.exists() ? { id: snap.id, ...snap.data() } : null;
}

// Retorna strains filtradas por tipo
export async function getStrainsPorTipo(tipo) {
  const snap = await getDocs(
    query(collection(db, "products"), where("type", "==", tipo))
  );
  return snap.docs.map(d => ({ id: d.id, ...d.data() }));
}

// ── PRODUTOS DA LOJA ──────────────────────────────────────
// Retorna todos os produtos da loja com nome do vendedor
export async function getProdutosLoja() {
  const [prodsSnap, usersSnap] = await Promise.all([
    getDocs(collection(db, "loja_produtos")),
    getDocs(collection(db, "users"))
  ]);

  const mapaVendedores = {};
  usersSnap.forEach(d => {
    mapaVendedores[d.id] = d.data().name || 'Vendedor';
  });

  return prodsSnap.docs.map(d => ({
    id: d.id,
    ...d.data(),
    vendedorNome: mapaVendedores[d.data().vendedorUid] || d.data().vendedorEmail || 'PhenoBrasil'
  }));
}

// Retorna produtos da loja de um vendedor específico
export async function getProdutosPorVendedor(uid) {
  const snap = await getDocs(
    query(collection(db, "loja_produtos"), where("vendedorUid", "==", uid))
  );
  return snap.docs.map(d => ({ id: d.id, ...d.data() }));
}

// Retorna categorias únicas dos produtos da loja
export async function getCategoriasProdutos() {
  const produtos = await getProdutosLoja();
  return [...new Set(produtos.map(p => p.categoria).filter(Boolean))].sort();
}

// Retorna um produto da loja pelo id
export async function getProduto(id) {
  const snap = await getDoc(doc(db, "loja_produtos", id));
  return snap.exists() ? { id: snap.id, ...snap.data() } : null;
}
