package burp;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class UiTextTest {
    @Test
    void englishIsUsedAsTheSourceAndDefaultLanguage() {
        assertEquals("Replace variables with their values...",
                UiText.get(UiLanguage.ENGLISH, "Replace variables with their values..."));
        assertEquals("Change variable folder...",
                UiText.get(UiLanguage.ENGLISH, "Change variable folder..."));
    }

    @Test
    void spanishTranslationsAreAvailableForTheRequestMenus() {
        assertEquals("Sustituir variables por sus valores...",
                UiText.get(UiLanguage.SPANISH, "Replace variables with their values..."));
        assertEquals("Cambiar carpeta de variables...",
                UiText.get(UiLanguage.SPANISH, "Change variable folder..."));
    }
}
