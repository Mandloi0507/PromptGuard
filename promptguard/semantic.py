# ============================================================
# semantic.py - Layer 2: Semantic (Meaning-Based) Analysis
# ============================================================
# Primary: sentence-transformers (all-MiniLM-L6-v2)
# Fallback: TF-IDF (scikit-learn)
# ============================================================

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

from .patterns import SEMANTIC_REFERENCES

_st_model = None
_st_available = None
_st_reference_vectors = {}
_tfidf_vectorizers = {}
_tfidf_reference_vectors = {}


def _try_load_st_model():
    """Try to load the sentence-transformers model. Returns model or None."""
    global _st_model, _st_available
    if _st_available is False:
        return None
    if _st_model is not None:
        return _st_model
    try:
        from sentence_transformers import SentenceTransformer

        print("[promptguard] Loading semantic model (first run, one-time download)...")
        _st_model = SentenceTransformer("all-MiniLM-L6-v2")
        _st_available = True
        print("[promptguard] Semantic model ready.")
        return _st_model
    except Exception as e:
        print(
            f"[promptguard] sentence-transformers unavailable ({e.__class__.__name__}). "
            "Using TF-IDF fallback for semantic layer."
        )
        _st_available = False
        return None


def _get_st_reference_vectors(st_model, attack_type: str, references: list):
    if attack_type not in _st_reference_vectors:
        _st_reference_vectors[attack_type] = st_model.encode(references)
    return _st_reference_vectors[attack_type]


def _tfidf_similarity(prompt: str, attack_type: str, references: list) -> float:
    """Compute similarity using cached TF-IDF reference vectors."""
    if attack_type not in _tfidf_vectorizers:
        vectorizer = TfidfVectorizer(ngram_range=(1, 2)).fit(references)
        _tfidf_vectorizers[attack_type] = vectorizer
        _tfidf_reference_vectors[attack_type] = vectorizer.transform(references)

    vectorizer = _tfidf_vectorizers[attack_type]
    prompt_vec = vectorizer.transform([prompt])
    scores = cosine_similarity(prompt_vec, _tfidf_reference_vectors[attack_type])
    return float(scores.max())


def get_semantic_score(prompt: str) -> tuple:
    """
    Calculate semantic similarity to known attack patterns.

    Returns (max_score, best_attack_type).
    """
    st_model = _try_load_st_model()

    best_score = 0.0
    best_type = None

    if st_model is not None:
        prompt_vector = st_model.encode([prompt])

    for attack_type, references in SEMANTIC_REFERENCES.items():
        if st_model is not None:
            ref_vectors = _get_st_reference_vectors(st_model, attack_type, references)
            scores = cosine_similarity(prompt_vector, ref_vectors)
            score = float(scores.max())
        else:
            score = _tfidf_similarity(prompt, attack_type, references)

        if score > best_score:
            best_score = score
            best_type = attack_type

    return best_score, best_type
