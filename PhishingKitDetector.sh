#!/bin/bash

# Vérif arg (besoin d'1 seul fichier)
if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <fichier_txt>"
    exit 1
fi

# Check si 'gobuster' est là
if ! command -v gobuster &> /dev/null; then
    echo "Erreur : 'gobuster' pas installé. Installez-le !"
    exit 1
fi

# Check si 'wget' est là
if ! command -v wget &> /dev/null; then
    echo "Erreur : 'wget' pas installé. Installez-le !"
    exit 1
fi

# Check si 'zipinfo' est là
if ! command -v zipinfo &> /dev/null; then
    echo "Erreur : 'zipinfo' pas installé. (Unzip ?)"
    exit 1
fi

# Récup fichier passé en param
file="$1"
if [ ! -f "$file" ]; then
    echo "Erreur : fichier $file introuvable."
    exit 1
fi

# Config
default_threads=100 # Threads pour booster
wordlist="/usr/share/wordlists/dirb/common.txt" # Liste mots pour scan
if [ ! -f "$wordlist" ]; then
    echo "Erreur : wordlist $wordlist introuvable."
    exit 1
fi

# Simplifie les URLs
normalize_url() {
    local url="$1"
    echo "$url" | awk -F/ '{print $1 "//" $3}'
}

# Lance gobuster
run_gobuster() {
    local url="$1"
    local output_file="$2"
    gobuster dir \
        -u "$url" \
        -w "$wordlist" \
        -x zip \ # Cherche les fichiers .zip
        -t "$default_threads" \
        -b 403,404,500,468,429 \ # Ignore ces codes HTTP
        -o "$output_file"
}

# Télécharge et check ZIP
fetch_and_inspect_zip() {
    local zip_url="$1"
    local destination_folder="$2"
    local zip_name="${zip_url##*/}"
    mkdir -p "$destination_folder" # Crée dossier si besoin
    local local_zip_path="${destination_folder}/${zip_name}"
    echo -e "Télécharge : $zip_url"
    wget -q "$zip_url" -O "$local_zip_path" # DL en silencieux
    if [ -f "$local_zip_path" ]; then
        echo "DL OK : $local_zip_path"
        echo "Type : $(file "$local_zip_path")"
        echo "Contenu ZIP :"
        zipinfo -1 "$local_zip_path" # Affiche contenu ZIP
    else
        echo "DL fail ou fichier absent."
    fi
}

# Scan chaque ligne du fichier
while IFS= read -r target_site; do
    if [ -n "$target_site" ]; then
        root_url=$(normalize_url "$target_site") # Clean URL
        domain=$(echo "$root_url" | awk -F/ '{print $3}') # Prend domaine
        output_file="gobuster_${domain}.txt"

        echo -e "\n-----------------------------------------"
        echo "Analyse : $root_url"
        echo "-----------------------------------------"
        run_gobuster "$root_url" "$output_file" # Lance scan
        if [ -f "$output_file" ]; then
            valid_paths=$(grep "Status: 200" "$output_file" | awk '{print $1}')  
            for path in $valid_paths; do
                if [[ "$path" == *".zip" ]]; then
                    # Si fichier ZIP trouvé
                    cleaned_path="${path#/}"
                    full_zip_url="$root_url/$cleaned_path"
                    zip_folder="zips_${domain}"
                    fetch_and_inspect_zip "$full_zip_url" "$zip_folder"
                else
                    # Si pas ZIP, rien
                    :
                fi
            done
        else
            echo "Fichier $output_file absent. Gobuster fail ?"
        fi
    fi
done < "$file"

echo -e "\nScans terminés.\n"
