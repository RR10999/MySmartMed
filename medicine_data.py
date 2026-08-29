"""
medicine_data.py
-----------------
Local, offline medicine name list used by the autocomplete feature
described in Section IV-D: "an autocomplete feature is implemented
which sources the data from National Databases... commonly
prescribed medicines sourced from publicly available pharmacological
databases."

For this offline-first prototype the list is bundled locally (no
network call is made at runtime, consistent with the offline-first
design goal) rather than fetched from an external API.
"""

COMMON_MEDICINES = [
    "Paracetamol", "Ibuprofen", "Amoxicillin", "Azithromycin", "Metformin",
    "Amlodipine", "Atorvastatin", "Losartan", "Omeprazole", "Pantoprazole",
    "Aspirin", "Clopidogrel", "Levothyroxine", "Metoprolol", "Furosemide",
    "Insulin Glargine", "Insulin Aspart", "Salbutamol", "Montelukast",
    "Cetirizine", "Loratadine", "Prednisolone", "Dexamethasone",
    "Ciprofloxacin", "Doxycycline", "Ranitidine", "Domperidone",
    "Ondansetron", "Diclofenac", "Naproxen", "Tramadol", "Gabapentin",
    "Pregabalin", "Sertraline", "Escitalopram", "Fluoxetine", "Alprazolam",
    "Diazepam", "Clonazepam", "Warfarin", "Rivaroxaban", "Apixaban",
    "Digoxin", "Simvastatin", "Rosuvastatin", "Glimepiride", "Gliclazide",
    "Pioglitazone", "Sitagliptin", "Empagliflozin", "Hydrochlorothiazide",
    "Enalapril", "Ramipril", "Telmisartan", "Valsartan", "Bisoprolol",
    "Carvedilol", "Nifedipine", "Spironolactone", "Vitamin D3", "Calcium Carbonate",
    "Folic Acid", "Iron (Ferrous Sulfate)", "Multivitamin", "Melatonin",
    "Zolpidem", "Amitriptyline", "Baclofen", "Tamsulosin", "Finasteride",
    "Sildenafil", "Metronidazole", "Fluconazole", "Acyclovir", "Prednisone",
    "Hydrocortisone Cream", "Mupirocin", "Loperamide", "Lactulose",
    "Ispaghula Husk", "Esomeprazole", "Famotidine",
]


def search_medicines(query: str, limit: int = 8):
    """Case-insensitive prefix/substring match against the local list."""
    if not query:
        return []
    q = query.strip().lower()
    starts = [m for m in COMMON_MEDICINES if m.lower().startswith(q)]
    contains = [m for m in COMMON_MEDICINES if q in m.lower() and m not in starts]
    return (starts + contains)[:limit]
