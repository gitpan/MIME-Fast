
MODULE = MIME::Fast		PACKAGE = MIME::Fast::Charset		PREFIX=g_mime_charset_

void
g_mime_charset_init(mime_charset)
    MIME::Fast::Charset mime_charset

const char *
g_mime_charset_locale_name()

 # needed only for non iso8859-1 locales
void
g_mime_charset_map_init()

#if GMIME_CHECK_VERSION_2_0_9 

const char *
g_mime_charset_language(charset)
	const char *	charset

#endif
	
const char *
g_mime_charset_best_name(mime_charset)
	MIME::Fast::Charset mime_charset

const char *
g_mime_charset_best(svtext)
        SV *	svtext
    PREINIT:
	char *	data;
	STRLEN	len;
    CODE:
        data = (char *)SvPV(svtext, len);
	RETVAL = g_mime_charset_best(data, len);
    OUTPUT:
	RETVAL


