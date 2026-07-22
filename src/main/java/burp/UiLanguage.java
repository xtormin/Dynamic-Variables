package burp;

enum UiLanguage {
    ENGLISH("en"),
    SPANISH("es");

    private final String code;

    UiLanguage(String code) {
        this.code = code;
    }

    String code() {
        return code;
    }

    static UiLanguage fromCode(String code) {
        for (UiLanguage language : values()) {
            if (language.code.equalsIgnoreCase(code)) return language;
        }
        return ENGLISH;
    }
}
