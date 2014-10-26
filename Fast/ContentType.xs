
MODULE = MIME::Fast		PACKAGE = MIME::Fast::ContentType		PREFIX=g_mime_content_type_

MIME::Fast::ContentType
g_mime_content_type_new(Class = "MIME::Fast::ContentType", name = 0, subname = 0)
    CASE: items == 2
        char *		Class;
        const char *	name;
    CODE:
        RETVAL = g_mime_content_type_new_from_string(name);
        plist = g_list_prepend(plist, RETVAL);
    OUTPUT:
        RETVAL
    CASE: items == 3
        char *		Class;
        const char *	name;
        const char *	subname;
    CODE:
        RETVAL = g_mime_content_type_new(name, subname);
        plist = g_list_prepend(plist, RETVAL);
    OUTPUT:
        RETVAL

void
DESTROY(mime_type)
        MIME::Fast::ContentType		mime_type
    CODE:
        if (gmime_debug)
	  warn("g_mime_content_type_DESTROY: 0x%x", mime_type);
        if (g_list_find(plist,mime_type)) {
          g_mime_content_type_destroy(mime_type);
          plist = g_list_remove(plist, mime_type);
        }

SV *
g_mime_content_type_to_string(mime_type)
        MIME::Fast::ContentType		mime_type
    PREINIT:
	char *	type;
    CODE:
	type = g_mime_content_type_to_string(mime_type);
	if (!type)
	  XSRETURN_UNDEF;
	RETVAL = newSVpv(type, 0);
	g_free (type);
    OUTPUT:
	RETVAL

gboolean
g_mime_content_type_is_type(mime_type, type, subtype)
        MIME::Fast::ContentType		mime_type
        const char *			type
        const char *			subtype

void
g_mime_content_type_set_parameter(mime_type, attribute, value)
        MIME::Fast::ContentType		mime_type
        const char *			attribute
        const char *			value

const char *
g_mime_content_type_get_parameter(mime_type, attribute)
        MIME::Fast::ContentType		mime_type
        const char *			attribute

char *
type(ctype)
        MIME::Fast::ContentType	ctype
    CODE:
        RETVAL = ctype->type;
    OUTPUT:
        RETVAL
        
char *
subtype(ctype)
        MIME::Fast::ContentType	ctype
    CODE:
        RETVAL = ctype->subtype;
    OUTPUT:
        RETVAL

