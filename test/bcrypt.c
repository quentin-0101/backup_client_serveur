#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <bcrypt.h>

#define SALT_SIZE 16

void generate_salt(char *salt) {
    for (int i = 0; i < SALT_SIZE; ++i) {
        salt[i] = (char)('a' + rand() % 26);
    }
}

int main() {
    char password[100];
    char salt[SALT_SIZE];
    char hashed_password[64]; // Bcrypt génère une chaîne de hachage de 60 caractères

    printf("Entrez le mot de passe à hasher : ");
    fgets(password, sizeof(password), stdin);
    password[strcspn(password, "\n")] = 0; // Supprime le caractère de nouvelle ligne

    generate_salt(salt);

    if (bcrypt_hashpw(password, salt, hashed_password) == 0) {
        printf("Mot de passe hashé : %s\n", hashed_password);
    } else {
        fprintf(stderr, "Erreur lors du hachage du mot de passe.\n");
    }

    return 0;
}
