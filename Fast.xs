#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#ifndef PL_sv_undef
#ifdef sv_undef
# define PL_sv_undef sv_undef
#endif
#endif

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <glib.h>
#include <gmime/gmime.h>

gboolean gmime_debug = 0;

struct raw_header {
    struct raw_header *next;
    char *name;
    char *value;
};			

typedef struct _GMimeHeader {
        GHashTable *hash;
        struct raw_header *headers;
} local_GMimeHeader;	

static int
not_here(char *s)
{
    croak("%s not implemented on this architecture", s);
    return -1;
}

#define GMIME_LENGTH_ENCODED 1
#define GMIME_LENGTH_CUMULATIVE 2

void
warn_type(SV *svmixed, gchar *text)
{
  SV		*svval;
  svtype	svvaltype;
  gchar		*svtext;
  STRLEN	vallen;

  svval = svmixed;
  if (SvROK(svmixed)) {
    svval = SvRV(svmixed);
  }
  svvaltype = SvTYPE(svval);

  svtext =
    (svvaltype == SVt_NULL) ?
        "SVt_NULL" :      /* 0 */
    (svvaltype == SVt_IV) ?
        "SVt_IV" :        /* 1 */
    (svvaltype == SVt_NV) ?
        "SVt_NV" :        /* 2 */
    (svvaltype == SVt_RV) ?
        "SVt_RV" :        /* 3 */
    (svvaltype == SVt_PV) ?
        "SVt_PV" :        /* 4 */
    (svvaltype == SVt_PVIV) ?
        "SVt_PVIV" :      /* 5 */
    (svvaltype == SVt_PVNV) ?
        "SVt_PVNV" :      /* 6 */
    (svvaltype == SVt_PVMG) ?
        "SVt_PVMG" :      /* 7 */
    (svvaltype == SVt_PVBM) ?
        "SVt_PVBM" :      /* 8 */
    (svvaltype == SVt_PVLV) ?
        "SVt_PVLV" :      /* 9 */
    (svvaltype == SVt_PVAV) ?
        "SVt_PVAV" :      /* 10 */
    (svvaltype == SVt_PVHV) ?
        "SVt_PVHV" :      /* 11 */
    (svvaltype == SVt_PVCV) ?
        "SVt_PVCV" :      /* 12 */
    (svvaltype == SVt_PVGV) ?
        "SVt_PVGV" :      /* 13 */
    (svvaltype == SVt_PVFM) ?
        "SVt_PVFM" :      /* 14 */
    (svvaltype == SVt_PVIO) ?
        "SVt_PVIO" :      /* 15 */
        "Unknown";

  warn("warn_type '%s': %s%d / %s, value='%s'", text,
    (SvROK(svmixed)) ? "ref " : "",
    (int)svvaltype,
    svtext,
    SvOK(svval) ? SvPV(svval, vallen) : "undef");
  
}

static int
constant(char *name, int len, int arg)
{
    errno = 0;
    switch (*name) {
    case 'G':
      if (strnEQ(name, "GMIME_", 6)) {
        switch (*(name+6)) {
        case 'L':
          if (strEQ(name, "GMIME_LENGTH_ENCODED"))
            return GMIME_LENGTH_ENCODED;
          else if (strEQ(name, "GMIME_LENGTH_CUMULATIVE"))
            return GMIME_LENGTH_CUMULATIVE;
          break;
        case 'P':
          if (strEQ(name, "GMIME_PART_ENCODING_DEFAULT"))
            return GMIME_PART_ENCODING_DEFAULT;
          else if (strEQ(name, "GMIME_PART_ENCODING_7BIT"))
            return GMIME_PART_ENCODING_7BIT;
          else if (strEQ(name, "GMIME_PART_ENCODING_8BIT"))
            return GMIME_PART_ENCODING_8BIT;
          else if (strEQ(name, "GMIME_PART_ENCODING_BASE64"))
            return GMIME_PART_ENCODING_BASE64;
          else if (strEQ(name, "GMIME_PART_ENCODING_QUOTEDPRINTABLE"))
            return GMIME_PART_ENCODING_QUOTEDPRINTABLE;
          else if (strEQ(name, "GMIME_PART_NUM_ENCODINGS"))
            return GMIME_PART_NUM_ENCODINGS;
          break;
        }
      }
      break;
    case 'I':
      if (strEQ(name, "INTERNET_ADDRESS_NONE"))
        return INTERNET_ADDRESS_NONE;
      else if (strEQ(name, "INTERNET_ADDRESS_NAME"))
        return INTERNET_ADDRESS_NAME;
      else if (strEQ(name, "INTERNET_ADDRESS_GROUP"))
        return INTERNET_ADDRESS_GROUP;
    } 
    errno = EINVAL;
    return 0;
not_there:
    errno = ENOENT;
    return 0;
}

/* enums */
typedef GMimePartEncodingType	MIME__Fast__PartEncodingType;
typedef InternetAddressType	MIME__Fast__InternetAddressType;

/* C types */
typedef GMimeParam *		MIME__Fast__Param;
typedef GMimePart *		MIME__Fast__Part;
typedef GMimeMessage *		MIME__Fast__Message;
typedef InternetAddress *	MIME__Fast__InternetAddress;
typedef GMimeContentType *	MIME__Fast__ContentType;
typedef GMimeStream *		MIME__Fast__Stream;
typedef GMimeDataWrapper *	MIME__Fast__DataWrapper;
typedef GMimeFilter *		MIME__Fast__Filter;

/*
 * Declarations for message header hash array
 */
#include "gmime-newfunc.c"
#include "gmime-newfuncheader.c"

static gboolean
recipients_destroy (gpointer key, gpointer value, gpointer user_data)
{
        GList *recipients = value;
        
        if (recipients) {
        	GList *recipient;
        	
        	recipient = recipients;
        	while (recipient) {
        		internet_address_destroy (recipient->data);
        		recipient = recipient->next;
        	}
        	
        	g_list_free (recipients);
        }
        
        return TRUE;
}


typedef struct {
        int			keyindex;	/* key index for firstkey */
        gchar			*fetchvalue;	/* value for each() method fetched with FETCH */
        MIME__Fast__Message	objptr;		/* any object pointer */
} hash_header;

typedef hash_header *	MIME__Fast__Hash__Header;

//const gchar *g_mime_message_get_sender (GMimeMessage *message);

/*
 * Double linked list of perl allocated pointers (for DESTROY xsubs)
 */
static GList *plist = NULL;

/*
 * Calling callback function for each mime part
 * TODO: change it from static to data pointer variable
 */
static SV * foreach_sub = (SV*)NULL;

static void
call_sub_foreach(GMimePart *mime_part, gpointer data)
{
    SV * svpart;
    SV * svdata;
    SV * rvpart;
    HV * stash;


    dSP ;

    svpart = sv_newmortal();
    svdata = sv_mortalcopy((SV *)(data));
    rvpart = sv_setref_pv(svpart, "MIME::Fast::Part", (MIME__Fast__Part)mime_part);
    if (gmime_debug)
    warn("function call_sub_foreach: setref (not in plist) MIME::Fast::Part 0x%x", mime_part);
    PUSHMARK(sp);
    XPUSHs(rvpart);
    XPUSHs(svdata);
    PUTBACK ;
    if (foreach_sub)
      perl_call_sv(foreach_sub, G_DISCARD);
}

/*
 * Returns content length of the given mime part and its descendants
 */
static guint
get_content_length(GMimePart *mime_part, int method)
{
        guint lsize = 0;

        if (mime_part) {
        	lsize = (mime_part->content && mime_part->content->stream) ?
        	  g_mime_stream_length(mime_part->content->stream) : 0; 
        	if ((method & GMIME_LENGTH_ENCODED) && lsize) {
        		GMimePartEncodingType	enc;

        		enc = g_mime_part_get_encoding(mime_part);
        		switch (enc) {
        		  case GMIME_PART_ENCODING_BASE64:
        		    lsize = BASE64_ENCODE_LEN(lsize);
        		    break;
        		  case GMIME_PART_ENCODING_QUOTEDPRINTABLE:
        		    lsize = QP_ENCODE_LEN(lsize);
        		    break;
        		}
        	}
        	if ((method & GMIME_LENGTH_CUMULATIVE) && mime_part->children) {
        		GList *child = mime_part->children;
        		while (child) {
        			lsize += get_content_length ( (GMimePart *) child->data, method );
        			child = child->next;
        		}
        	}
        }
        return lsize;
}

MODULE = MIME::Fast		PACKAGE = MIME::Fast		


double
constant(sv,arg)
    PREINIT:
        STRLEN		len;
    INPUT:
        SV *		sv
        char *		s = SvPV(sv, len);
        int		arg
    CODE:
        RETVAL = constant(s,len,arg);
    OUTPUT:
        RETVAL

MODULE = MIME::Fast		PACKAGE = MIME::Fast::Param		PREFIX=g_mime_param_

MIME::Fast::Param
g_mime_param_new(Class = "MIME::Fast::Param", name = 0, value = 0)
    CASE: items == 2
        char *		Class;
        const gchar *	name;
    CODE:
        RETVAL = g_mime_param_new_from_string(name);
    OUTPUT:
        RETVAL
    CASE: items == 3
        char *		Class;
        const gchar *	name;
        const gchar *	value;
    CODE:
        RETVAL = g_mime_param_new(name, value);
        plist = g_list_prepend(plist, RETVAL);
    OUTPUT:
        RETVAL

void
DESTROY(param)
        MIME::Fast::Param	param
    CODE:
        if (g_list_find(plist,param)) {
          g_mime_param_destroy (param);
          plist = g_list_remove(plist, param);
        }

gchar *
g_mime_param_to_string(param)
        MIME::Fast::Param	param

MODULE = MIME::Fast		PACKAGE = MIME::Fast::ContentType		PREFIX=g_mime_content_type_

MIME::Fast::ContentType
g_mime_content_type_new(Class = "MIME::Fast::ContentType", name = 0, subname = 0)
    CASE: items == 2
        char *		Class;
        const gchar *	name;
    CODE:
        RETVAL = g_mime_content_type_new_from_string(name);
        plist = g_list_prepend(plist, RETVAL);
    OUTPUT:
        RETVAL
    CASE: items == 3
        char *		Class;
        const gchar *	name;
        const gchar *	subname;
    CODE:
        RETVAL = g_mime_content_type_new(name, subname);
        plist = g_list_prepend(plist, RETVAL);
    OUTPUT:
        RETVAL

void
DESTROY(mime_type)
        MIME::Fast::ContentType	mime_type
    CODE:
        if (g_list_find(plist,mime_type)) {
          g_mime_content_type_destroy(mime_type);
          plist = g_list_remove(plist, mime_type);
        }

gchar *
g_mime_content_type_to_string(mime_type)
        MIME::Fast::ContentType	mime_type

gboolean
g_mime_content_type_is_type(mime_type, type, subtype)
        MIME::Fast::ContentType	mime_type
        const gchar *			type
        const gchar *			subtype

void
g_mime_content_type_add_parameter(mime_type, attribute, value)
        MIME::Fast::ContentType	mime_type
        const gchar *			attribute
        const gchar *			value

gchar *
g_mime_content_type_get_parameter(mime_type, attribute)
        MIME::Fast::ContentType	mime_type
        const gchar *			attribute

gchar *
type(ctype)
        MIME::Fast::ContentType	ctype
    CODE:
        RETVAL = ctype->type;
    OUTPUT:
        RETVAL
        
gchar *
subtype(ctype)
        MIME::Fast::ContentType	ctype
    CODE:
        RETVAL = ctype->subtype;
    OUTPUT:
        RETVAL

MODULE = MIME::Fast		PACKAGE = MIME::Fast::Part		PREFIX=g_mime_part_

 #
 ## CONSTRUCTION/DESCTRUCTION
 #

MIME::Fast::Part
g_mime_part_new(Class = "MIME::Fast::Part", type = "text", subtype = "plain")
        char *		Class;
        const gchar *		type;
        const gchar *		subtype;
    PROTOTYPE: $;$$
    CODE:
        RETVAL = g_mime_part_new_with_type(type, subtype);
        plist = g_list_prepend(plist, RETVAL);
        if (gmime_debug)
        warn("function g_mime_part_new (also in plist): 0x%x", RETVAL);
    OUTPUT:
        RETVAL

void
DESTROY(mime_part)
        MIME::Fast::Part	mime_part
    CODE:
        if (gmime_debug)
          warn("g_mime_part_DESTROY: 0x%x %s", mime_part,
          g_list_find(plist,mime_part) ? "(true destroy)" : "(only attempt)");
        if (g_list_find(plist,mime_part)) {
          g_mime_part_destroy(mime_part);
          plist = g_list_remove(plist, mime_part);
        }

 #
 ## ACCESSOR FUNCTIONS
 #

 ## INTERFACE: keyword does not work with perl v5.6.0
 ## (unknown cv variable during C compilation)
 
 #
 # void
 # interface_s_ss(mime_part, value)
 #	MIME::Fast::Part	mime_part
 #	gchar *		value
 #    INTERFACE:
 #	g_mime_part_set_content_description
 #	g_mime_part_set_content_id
 #

 #
 # description
 #
void
g_mime_part_set_content_description(mime_part, description)
        MIME::Fast::Part	mime_part
        const gchar *	description
    CODE:
        g_mime_part_set_content_description(mime_part, description);

const gchar *
g_mime_part_get_content_description(mime_part)
        MIME::Fast::Part	mime_part
    CODE:
        RETVAL = g_mime_part_get_content_description(mime_part);
    OUTPUT:
    	RETVAL

 #
 # content_id
 #
void
g_mime_part_set_content_id(mime_part, content_id)
        MIME::Fast::Part	mime_part
        const gchar *	content_id

const gchar *
g_mime_part_get_content_id(mime_part)
        MIME::Fast::Part	mime_part
    CODE:
        RETVAL = g_mime_part_get_content_id(mime_part);
    OUTPUT:
    	RETVAL

 #
 # content_md5
 #
void
g_mime_part_set_content_md5(mime_part, content_md5)
        MIME::Fast::Part	mime_part
        const gchar *	content_md5

gboolean
g_mime_part_verify_content_md5(mime_part)
        MIME::Fast::Part	mime_part
        
const gchar *
g_mime_part_get_content_md5(mime_part)
        MIME::Fast::Part	mime_part
    CODE:
        RETVAL = g_mime_part_get_content_md5(mime_part);
    OUTPUT:
    	RETVAL

 #
 # content_location
 #
void
g_mime_part_set_content_location(mime_part, content_location)
        MIME::Fast::Part	mime_part
        const gchar *	content_location

const gchar *
g_mime_part_get_content_location(mime_part)
        MIME::Fast::Part	mime_part
    CODE:
        RETVAL = g_mime_part_get_content_location(mime_part);
    OUTPUT:
    	RETVAL

 #
 # content_length
 #
guint
g_mime_part_get_content_length(mime_part, method = GMIME_LENGTH_CUMULATIVE)
        MIME::Fast::Part	mime_part
        int			method
    CODE:
        RETVAL = get_content_length(mime_part, method);
    OUTPUT:
    	RETVAL


 #
 # content_type
 #
void
g_mime_part_set_content_type(mime_part, content_type)
        MIME::Fast::Part		mime_part
        MIME::Fast::ContentType	content_type
    CODE:
        g_mime_part_set_content_type(mime_part, content_type);
        plist = g_list_remove(plist, content_type);

MIME::Fast::ContentType
g_mime_part_get_content_type(mime_part)
        MIME::Fast::Part	mime_part
    CODE:
        RETVAL = g_mime_part_get_content_type(mime_part);
    OUTPUT:
    	RETVAL

 #
 # encoding
 #
void
g_mime_part_set_encoding(mime_part, encoding)
        MIME::Fast::Part			mime_part
        MIME::Fast::PartEncodingType		encoding
    CODE:
        g_mime_part_set_encoding(mime_part, encoding);

MIME::Fast::PartEncodingType
g_mime_part_get_encoding(mime_part)
        MIME::Fast::Part	mime_part
    CODE:
        RETVAL = g_mime_part_get_encoding(mime_part);
    OUTPUT:
    	RETVAL

 #
 # encoding<->string
 #
const gchar *
g_mime_part_encoding_to_string(encoding)
        MIME::Fast::PartEncodingType		encoding
        # TODO - how call it
    CODE:
        RETVAL = g_mime_part_encoding_to_string(encoding);
    OUTPUT:
    	RETVAL

MIME::Fast::PartEncodingType
g_mime_part_encoding_from_string(encoding)
        const gchar *		encoding
    CODE:
        RETVAL = g_mime_part_encoding_from_string(encoding);
    OUTPUT:
    	RETVAL

 #
 # content_disposition
 #
void
g_mime_part_set_content_disposition(mime_part, disposition)
        MIME::Fast::Part	mime_part
        const gchar *		disposition
    CODE:
        g_mime_part_set_content_disposition(mime_part, disposition);

gchar *
g_mime_part_get_content_disposition(mime_part)
        MIME::Fast::Part	mime_part
    CODE:
        RETVAL = g_mime_part_get_content_disposition(mime_part);
    OUTPUT:
    	RETVAL

 #
 # content_disposition_parameter
 #
void
g_mime_part_add_content_disposition_parameter(mime_part, name, value)
        MIME::Fast::Part	mime_part
        const gchar *	name
        const gchar *	value
    CODE:
        g_mime_part_add_content_disposition_parameter(mime_part, name, value);

const gchar *
g_mime_part_get_content_disposition_parameter(mime_part, name)
        MIME::Fast::Part	mime_part
        const gchar *	name
    CODE:
        RETVAL = g_mime_part_get_content_disposition_parameter(mime_part, name);
    OUTPUT:
    	RETVAL

 #
 # filename
 #
void
g_mime_part_set_filename(mime_part, filename)
        MIME::Fast::Part	mime_part
        const gchar *	filename
    CODE:
        g_mime_part_set_filename(mime_part, filename);

const gchar *
g_mime_part_get_filename(mime_part)
        MIME::Fast::Part	mime_part
    CODE:
        RETVAL = g_mime_part_get_filename(mime_part);
    OUTPUT:
    	RETVAL

 #
 # boundary
 #
void
g_mime_part_set_boundary(mime_part, boundary)
        MIME::Fast::Part	mime_part
        const gchar *	boundary
    CODE:
        g_mime_part_set_boundary(mime_part, boundary);

const gchar *
g_mime_part_get_boundary(mime_part)
        MIME::Fast::Part	mime_part
    CODE:
        RETVAL = g_mime_part_get_boundary(mime_part);
    OUTPUT:
    	RETVAL

 #
 # content
 #
void
g_mime_part_set_content(mime_part, svmixed)
        MIME::Fast::Part	mime_part
        SV *		        svmixed
    PREINIT:
        char *	data;
        STRLEN	len;
        SV*     svval;
        GMimeStream	        *mime_stream = NULL;
        GMimeDataWrapper	*mime_data_wrapper = NULL;
        svtype	svvaltype;
    CODE:
    	svval = svmixed;
        if (SvROK(svmixed)) {
          if (sv_derived_from(svmixed, "MIME::Fast::DataWrapper")) {
          	IV tmp = SvIV((SV*)SvRV(svmixed));
        	GMimeDataWrapper *mime_data_wrapper;

        	mime_data_wrapper = INT2PTR(MIME__Fast__DataWrapper,tmp);
        	g_mime_part_set_content_object(mime_part, mime_data_wrapper);
            return;
          } else if (sv_derived_from(svmixed, "MIME::Fast::Stream")) {
          	IV tmp = SvIV((SV*)SvRV(svmixed));

        	mime_stream = INT2PTR(MIME__Fast__Stream,tmp);
            mime_data_wrapper = g_mime_data_wrapper_new_with_stream(mime_stream, GMIME_PART_ENCODING_BASE64);
            g_mime_part_set_content_object(mime_part, mime_data_wrapper);
            return;
          }
          svval = SvRV(svmixed);
        }
        svvaltype = SvTYPE(svval);

        if (svvaltype == SVt_PVGV) { // possible FILE * handle
          FILE *  fp = IoIFP(sv_2io(svval));

          mime_stream = g_mime_stream_file_new(fp);
          ((GMimeStreamFile *)mime_stream)->owner = FALSE;
          mime_data_wrapper = g_mime_data_wrapper_new_with_stream(mime_stream, GMIME_PART_ENCODING_BASE64);
          g_mime_part_set_content_object(mime_part, mime_data_wrapper);

          g_mime_stream_unref(mime_stream);
        } else if (SvPOK(svval)) {
          data = (gchar *)SvPV(svval, len);
          g_mime_part_set_content(mime_part, data, len);
        } else {
          warn_type(svval,"mime_set_content error");
          croak("mime_set_content: Unknown type: %d", (int)svvaltype);
        }
 
 # g_mime_part_set_content_byte_array is not supported

void
g_mime_part_set_pre_encoded_content(mime_part, content, encoding)
        MIME::Fast::Part	mime_part
        SV *		content
        MIME::Fast::PartEncodingType	encoding
    PREINIT:
        char *	data;
        STRLEN	len;
    CODE:
        data = SvPV(content, len);
        g_mime_part_set_pre_encoded_content(mime_part, data, len, encoding);

MIME::Fast::DataWrapper
g_mime_part_get_content_object(mime_part)
        MIME::Fast::Part	mime_part
    CODE:
        RETVAL = g_mime_part_get_content_object(mime_part);
    OUTPUT:
    	RETVAL

 #
 # get_content
 #
SV *
g_mime_part_get_content(mime_part)
        MIME::Fast::Part	mime_part
    PREINIT:
        guint len;
        const gchar * content_char;
        SV * content;

    CODE:
    /*
        content_char = g_mime_part_get_content(mime_part, &len);
        if (content_char)
          content = newSVpv(content_char, len);
        RETVAL = content;
     */
        ST(0) = &PL_sv_undef;
        if (!(mime_part->content) || !(mime_part->content->stream) ||
             (content_char = g_mime_part_get_content(mime_part, &len)) == NULL)
          return;
        content = sv_newmortal();
        SvUPGRADE(content, SVt_PV);
        SvREADONLY_on(content);
        SvPVX(content) = (char *) (content_char);
        SvCUR_set(content, len);
        SvLEN_set(content, 0);
        SvPOK_only(content);
        ST(0) = content;


 #
 # add child/subpart
 #
void
g_mime_part_add_subpart(mime_part, subpart)
        MIME::Fast::Part	mime_part
        MIME::Fast::Part	subpart
    CODE:
        g_mime_part_add_subpart(mime_part, subpart);
        plist = g_list_remove(plist, subpart);

 #
 ## UTILITY FUNCTIONS
 #

 #
 # write_to_stream
 #
void
g_mime_part_write_to_stream(mime_part, mime_stream)
        MIME::Fast::Part	mime_part
        MIME::Fast::Stream	mime_stream
    CODE:
        g_mime_part_write_to_stream(mime_part, mime_stream);

 #
 # (part_)to_string
 #
gchar *
g_mime_part_to_string(mime_part)
        MIME::Fast::Part	mime_part
    CODE:
        RETVAL = g_mime_part_to_string(mime_part);
    OUTPUT:
        RETVAL


 #
 # callback function
 #
void
g_mime_part_foreach_part(mime_part, callback, svdata)
        MIME::Fast::Part		mime_part
        SV *			callback
        SV *			svdata
    PREINIT:
        gpointer		data;

    CODE:
        data = (gpointer)svdata;
        if (foreach_sub == (SV*)NULL)
            foreach_sub = newSVsv(callback);
        else
            SvSetSV(foreach_sub, callback);
        g_mime_part_foreach(mime_part, call_sub_foreach, data);
        SvSetSV(foreach_sub, (SV*)NULL);

 #
 # subpart
 #
MIME::Fast::Part
g_mime_part_get_subpart_from_content_id(mime_part, content_id)
        MIME::Fast::Part	mime_part
        const gchar *	content_id

 #
 # del_child
 # ALIAS: del_subpart
 #
void
g_mime_part_remove_subpart(mime_part, child)
        MIME::Fast::Part	mime_part
        MIME::Fast::Part	child
    ALIAS:
        MIME::Fast::Part::remove_child = 1
    CODE:
        if (gmime_debug)
        warn("g_mime_part_del_subpart: 0x%x, child=0x%x (add child to plist)", mime_part, child);
        g_mime_part_del_subpart(mime_part, child);
        //RETVAL = child;
        plist = g_list_prepend(plist, child);
        
 #
 # children
 # ALIAS: parts
 #
void
children(mime_part, ...)
        MIME::Fast::Part	mime_part
    ALIAS:
        MIME::Fast::Part::parts = 1
    PREINIT:
        GList *		child;
        AV * 		retav;
        IV		partnum = -1;
        I32		gimme = GIMME_V;
        gint		count = 0;
    PPCODE:
        if (items == 2) {
          partnum = SvIV(ST(1));
        }
        for (child = mime_part->children; child && child->data; child = child->next, ++count) {
          SV * part;
          if (items == 1 && gimme == G_SCALAR)
            continue;

          # avoid unnecessary SV creation
          if (items == 2 && partnum != count)
            continue;

          # push part
          part = sv_newmortal();
          sv_setref_pv(part, "MIME::Fast::Part", (MIME__Fast__Part)(child->data));
        if (gmime_debug)
          warn("function g_mime_part_children setref (not in plist): 0x%x", child->data);

          if (items == 1) {
            XPUSHs(part);
          } else if (partnum == count) {
              XPUSHs(part);
              break;
          }
        }
        if (gimme == G_SCALAR && partnum == -1)
          XPUSHs(sv_2mortal(newSViv(count)));
          
 # return mime part for the given numer(s)
SV *
g_mime_part_get_subpart_by_number(sv_main_part, ...)
        SV *		sv_main_part
    PREINIT:
        gint		i, count = 0;
        IV		partnum = -1;
        GMimePart	*part, *mime_part, *parent_part;
        GMimeMessage	*message;
        guint		len;
        SV *		retsv = NULL;
    CODE:
        /* retrieve mime_part */
        if (sv_derived_from(ST(0), "MIME::Fast::Part")) {
            IV tmp = SvIV((SV*)SvRV(ST(0)));
            mime_part = INT2PTR(MIME__Fast__Part,tmp);
        } else if (sv_derived_from(ST(0), "MIME::Fast::Message")) {
            IV tmp = SvIV((SV*)SvRV(ST(0)));
            message = INT2PTR(MIME__Fast__Message,tmp);
            mime_part = message->mime_part;
        }
        else
            croak("given message/part is not of type MIME::Fast::Part nor MIME::Fast::Message");
            
        /**/
        part = mime_part;
        parent_part = part;
        for (i=items - 1; part && i>0; --i) {
          partnum = SvIV(ST(items - i));
        if (gmime_debug)
          warn("subpart_by_number: part = 0x%x (%s), items = %d i = %d partnum(%d) = %d",
          	part, g_mime_content_type_to_string(g_mime_part_get_content_type(part)),
        	items, i, items - i, partnum);
          if (g_mime_content_type_is_type(g_mime_part_get_content_type(part),"message","rfc822")) {
            if (i == 1) { /* the last part we are looking for */
              /* construct new message from the attachment contents */
              gchar *part_content = g_mime_part_get_content(part, &len);
              GMimeStream *stream;

              stream = g_mime_stream_mem_new_with_buffer(part_content,len);
              message = g_mime_parser_construct_message(stream,1);
              g_mime_stream_unref(stream);
              if (gmime_debug)
                warn("construct_message from subpart 0x%x from data = 0x%x len = %d", message, part_content, len);
              plist = g_list_prepend(plist, message);
              /* g_mime_message_destroy (message); */
              RETVAL = sv_newmortal();
              sv_setref_pv(RETVAL, "MIME::Fast::Message", (MIME__Fast__Message)(message));
              retsv = RETVAL;
              if (gmime_debug)
              warn("function g_mime_part_subpart_by_number new MIME::Fast::Message: 0x%x", message);
              break;
            } else {
              SV * tmp;
              GMimeStream *stream;
              gchar *part_content = g_mime_part_get_content(part, &len);

              stream = g_mime_stream_mem_new_with_buffer(part_content,len);
              part = g_mime_parser_construct_part(stream);
              g_mime_stream_unref (stream);
              parent_part = part; /* it is parent part now */
              if (gmime_debug)
              warn("function g_mime_part_subpart_by_number new consctruct part: 0x%x (not in plist) from part 0x%x", part, parent_part);
              tmp = sv_newmortal();
              sv_setref_pv(tmp, "MIME::Fast::Part", (MIME__Fast__Part)(part));
              if (gmime_debug)
              warn("Put in plist Part 0x%x / part 0x%x", tmp, part);
              plist = g_list_prepend(plist, part);
            }
          } else if (g_mime_content_type_is_type(g_mime_part_get_content_type(part),"multipart","*")) {
            parent_part = part;
            part = g_list_nth_data(part->children, partnum);
          } else {
            die("Part 0x%x is not multipart only '%s'", part, g_mime_content_type_to_string(g_mime_part_get_content_type(part)));
          }
        }

        /* check if part is NULL */
        if (!part) {
          ST(0) = &PL_sv_undef;
          return;
        }

        if (part != parent_part)
          g_mime_part_del_subpart(parent_part, part);
          if (gmime_debug)
          warn("subpart_by_number: part = 0x%x (%s), items = %d i = %d partnum(%d) = %d",
          	part, g_mime_content_type_to_string(g_mime_part_get_content_type(part)),
        	items, i, items - i, partnum);
          if (gmime_debug)
        warn("subpart_by_number: end");
        if (!retsv) {
          RETVAL = sv_newmortal();
          sv_setref_pv(RETVAL, "MIME::Fast::Part", (MIME__Fast__Part)(part));
          if (part != mime_part)
            plist = g_list_prepend(plist, part);
          if (gmime_debug)
          warn("function g_mime_part_subpart_by_number returns part 0x%x in plist=%d", part, part != mime_part);
        }
    OUTPUT:
        RETVAL

MODULE = MIME::Fast		PACKAGE = MIME::Fast::Message	PREFIX=g_mime_message_

# new(pretty_headers)
MIME::Fast::Message
g_mime_message__new(Class, pretty_headers = FALSE)
        gchar *		Class
        gboolean	pretty_headers
    CODE:
        RETVAL = g_mime_message_new(pretty_headers);
        plist = g_list_prepend(plist, RETVAL);
    OUTPUT:
        RETVAL

# destroy(message)
void
DESTROY(message)
        MIME::Fast::Message	message
    CODE:
        if (gmime_debug)
          warn("g_mime_message_DESTROY: 0x%x", message);
        g_mime_message_destroy (message);

# sender
void
g_mime_message_set_sender(message, sender)
        MIME::Fast::Message	message
        const gchar *	sender

const gchar *
g_mime_message_get_sender(message)
        MIME::Fast::Message	message
        
# reply_to
void
g_mime_message_set_reply_to(message, reply_to)
        MIME::Fast::Message	message
        const gchar *	reply_to

const gchar *
g_mime_message_get_reply_to(message)
        MIME::Fast::Message	message
        
# recipient
void
g_mime_message_add_recipient(message, type, name, address)
        MIME::Fast::Message	message
        gchar *		type
        const gchar *	name
        const gchar *	address

void
g_mime_message_add_recipients_from_string(message, type, recipients)
 	MIME::Fast::Message	message
        gchar *		type
        const gchar *	recipients

AV *
g_mime_message_get_recipients(message, type)
        MIME::Fast::Message	message
        const gchar *	type
    PREINIT:
        GList *		rcpt;
        AV * 		retav;
    CODE:
        retav = newAV();
        rcpt = g_mime_message_get_recipients(message, type);
        while (rcpt && rcpt->data) {
          SV * address = newSViv(0);
          sv_setref_pv(address, "MIME::Fast::InternetAddress", (MIME__Fast__InternetAddress)(rcpt->data));
          av_push(retav, address);
          rcpt = rcpt->next;
        }
        RETVAL = retav;
    OUTPUT:
        RETVAL

# subject
void
g_mime_message_set_subject(message, subject)
        MIME::Fast::Message	message
        const gchar *	subject

const gchar *
g_mime_message_get_subject(message)
        MIME::Fast::Message	message
        
 # date
void
g_mime_message_set_date(message, date, gmt_offset)
        MIME::Fast::Message	message
        time_t		date
        int		gmt_offset

void
g_mime_message_set_date_from_string(message, str)
        MIME::Fast::Message	message
        const gchar *	str

 #
 # returns scalar string or array (date, gmt_offset)
 #
void
g_mime_message_get_date(message)
        MIME::Fast::Message	message
    PREINIT:
        time_t		date;
        int		gmt_offset;
        I32		gimme = GIMME_V;
    PPCODE:
        if (gimme == G_SCALAR) {
          gchar *str = g_mime_message_get_date_string(message);
          XPUSHs(sv_2mortal(newSVpv(str,0)));
        } else if (gimme == G_ARRAY) {
          g_mime_message_get_date(message, &date, &gmt_offset);
          XPUSHs(sv_2mortal(newSVnv(date)));
          XPUSHs(sv_2mortal(newSViv(gmt_offset)));
        }

# message_id
void
g_mime_message_set_message_id(message, message_id)
        MIME::Fast::Message	message
        const gchar *	message_id

const gchar *
g_mime_message_get_message_id(message)
        MIME::Fast::Message	message

# the other headers
void
g_mime_message_set_header(message, field, value)
        MIME::Fast::Message	message
        const gchar *	field
        const gchar *	value
    CODE:
        message_set_header(message, field, value);
    	

void
g_mime_message_remove_header(message, field)
        MIME::Fast::Message	message
        const gchar *	field
    CODE:
        message_remove_header(message, field);

# new function - add any header
void
g_mime_message_add_header(message, field, value)
        MIME::Fast::Message	message
        const gchar *	field
        const gchar *	value

# CODE:
#	message_set_header(message, field, value);

void
g_mime_message_get_header(message, field)
        MIME::Fast::Message	message
        const gchar *	field
    PREINIT:
        gint		i = 0;
        gchar *		enc_value = NULL;
        GList *		rcpt;
    PPCODE:

        for (i = 0; i < HEADER_UNKNOWN; ++i)
          if (!g_strncasecmp(field, fields[i], strlen(fields[i])))
            break;
        
        switch (i) {
        case HEADER_FROM:
          enc_value = g_mime_message_get_sender(message);
          break;
        case HEADER_REPLY_TO:
          enc_value = g_mime_message_get_reply_to(message);
          break;
        case HEADER_TO:
          rcpt = g_mime_message_get_recipients(message,
        	GMIME_RECIPIENT_TYPE_TO);
          while (rcpt && rcpt->data) {
            InternetAddress *ia = (InternetAddress *)(rcpt->data);
            enc_value = internet_address_to_string(ia, FALSE);
            /* XPUSHp(enc_value, (strlen(enc_value))); */
            XPUSHs(sv_2mortal(newSVpv(enc_value,0)));
            rcpt = rcpt->next;
          }
          enc_value = NULL;
          break;
        case HEADER_CC:
          rcpt = g_mime_message_get_recipients(message,
        	GMIME_RECIPIENT_TYPE_CC);
          while (rcpt && rcpt->data) {
            InternetAddress *ia = (InternetAddress *)(rcpt->data);
            enc_value = internet_address_to_string(ia, FALSE);
            XPUSHs(sv_2mortal(newSVpv(enc_value,0)));
            rcpt = rcpt->next;
          }
          enc_value = NULL;
          break;
        case HEADER_BCC:
          rcpt = g_mime_message_get_recipients(message,
        	GMIME_RECIPIENT_TYPE_BCC);
          while (rcpt && rcpt->data) {
            InternetAddress *ia = (InternetAddress *)(rcpt->data);
            enc_value = internet_address_to_string(ia, FALSE);
            XPUSHs(sv_2mortal(newSVpv(enc_value,0)));
            rcpt = rcpt->next;
          }
          enc_value = NULL;
          break;
        case HEADER_SUBJECT:
          enc_value = g_mime_message_get_subject(message);
          break;
        case HEADER_DATE:
          enc_value = g_mime_message_get_date_string(message);
          break;
        case HEADER_MESSAGE_ID:
          enc_value = g_mime_message_get_message_id(message);
          break;
        default: /* HEADER_UNKNOWN */
          {
            GList *gret = message_get_header(message, field);

            while (gret && gret->data) {
              enc_value = (gchar *)(gret->data);
              XPUSHs(sv_2mortal(newSVpv(enc_value,0)));
              gret = gret->next;
            }
          }
          /*
          enc_value = g_mime_message_get_header(message, field);
          for (i = 0; i < message->header->arbitrary_headers->len; i++) {
            const GMimeHeader *header;
          
            header = message->header->arbitrary_headers->pdata[i];
            if (!g_strncasecmp(field, header->name, strlen(header->name))) { 
              enc_value = g_mime_utils_8bit_header_encode (header->value);
              XPUSHs(sv_2mortal(newSVpv(enc_value,0)));
            }
          }
          enc_value = NULL;
          */
          break;
        }
        if (i != HEADER_UNKNOWN && enc_value)
          XPUSHs(sv_2mortal(newSVpv(enc_value,0)));

# mime_part
void
g_mime_message_set_mime_part(message, mime_part)
        MIME::Fast::Message	message
        MIME::Fast::Part	mime_part
    CODE:
        g_mime_message_set_mime_part(message, mime_part);
        plist = g_list_remove(plist, mime_part);

## UTILITY FUNCTIONS

 #
 # write_to_stream
 #
void
g_mime_message_write_to_stream(message, mime_stream)
        MIME::Fast::Message	message
        MIME::Fast::Stream	mime_stream
    CODE:
        g_mime_message_write_to_stream(message, mime_stream);
        
gchar *
g_mime_message_to_string(message)
        MIME::Fast::Message	message

gchar *
g_mime_message_get_body(message, want_plain = 1, is_html = 0)
    CASE: items == 1
        MIME::Fast::Message	message
    PREINIT:
        gboolean	want_plain = 1;
        gboolean	is_html;
    CODE:
        RETVAL = g_mime_message_get_body(message, want_plain, &is_html);
    OUTPUT:
        RETVAL
    CASE: items == 2
        MIME::Fast::Message	message
        gboolean	want_plain
    PREINIT:
        gboolean	is_html;
    CODE:
        RETVAL = g_mime_message_get_body(message, want_plain, &is_html);
    OUTPUT:
        RETVAL
    CASE: items == 3
        MIME::Fast::Message	message
        gboolean	want_plain
        gboolean	&is_html
    OUTPUT:
        is_html
        RETVAL
        

gchar *
g_mime_message_get_headers(message)
        MIME::Fast::Message	message

# callback function
void
g_mime_message_foreach_part(message, callback, svdata)
        MIME::Fast::Message	message
        SV *			callback
        SV *			svdata
    PREINIT:
        gpointer		data;

    CODE:
/**/
        data = (gpointer)svdata;
        if (foreach_sub == (SV*)NULL)
            foreach_sub = newSVsv(callback);
        else
            SvSetSV(foreach_sub, callback);
        g_mime_message_foreach_part(message, call_sub_foreach, data);
        SvSetSV(foreach_sub, (SV*)NULL);
/**/

## "OBJECTS" FUNCTION

MIME::Fast::Part
get_mime_part(message)
        MIME::Fast::Message	message
    CODE:
        RETVAL = message->mime_part;
        if (gmime_debug)
          warn("function message->mime_part returns (not in plist): 0x%x", RETVAL);
    OUTPUT:
        RETVAL


MODULE = MIME::Fast		PACKAGE = MIME::Fast::InternetAddress	PREFIX=internet_address_

MIME::Fast::InternetAddress
internet_address_new(Class, name, address)
    CASE: items <= 1
        char *		Class
    CODE:
        RETVAL = internet_address_new();
        plist = g_list_prepend(plist, RETVAL);
    OUTPUT:
        RETVAL
    CASE: items == 2
        char *		Class
        gchar *		name
    CODE:
        RETVAL = internet_address_new_group(name);
        plist = g_list_prepend(plist, RETVAL);
    OUTPUT:
        RETVAL
    CASE: items == 3
        char *		Class
        gchar *		name
        gchar *		address
    CODE:
        RETVAL = internet_address_new_name(name, address);
        plist = g_list_prepend(plist, RETVAL);
    OUTPUT:
        RETVAL

void
DESTROY(ia)
        MIME::Fast::InternetAddress	ia
    CODE:
        if (g_list_find(plist,ia)) {
          internet_address_destroy(ia);
          plist = g_list_remove(plist, ia);
        }

AV *
internet_address_parse_string(str)
        const gchar *		str
    PREINIT:
        GList *		addrlist;
        AV * 		retav;
    CODE:
        addrlist = internet_address_parse_string(str);
        while (addrlist && addrlist->data) {
          SV * address = newSViv(0);
          sv_setref_pv(address, "MIME::Fast::InternetAddress", (MIME__Fast__InternetAddress)(addrlist->data));
          av_push(retav, address);
          addrlist = addrlist->next;
        }
        RETVAL = retav;
    OUTPUT:
        RETVAL

gchar *
internet_address_to_string(ia, encode = TRUE)
        MIME::Fast::InternetAddress	ia
        gboolean		encode

void
internet_address_set_name(ia, name)
        MIME::Fast::InternetAddress	ia
        const gchar *		name

void
internet_address_set_addr(ia, addr)
        MIME::Fast::InternetAddress	ia
        const gchar *		addr

void
internet_address_set_group(ia, ...)
        MIME::Fast::InternetAddress	ia
    PREINIT:
        MIME__Fast__InternetAddress	addr;
        GList *			addrlist = NULL;
        int			i;
    CODE:
        if (items < 2) {
          croak("Usage: internet_address_set_group(InternetAddr, [InternetAddr]+");
          return;
        }
        for (i=items - 1; i>0; --i) {
          /* retrieve each address from the perl array */
          if (sv_derived_from(ST(items - i), "MIME::Fast::InternetAddress")) {
            IV tmp = SvIV((SV*)SvRV(ST(items - i)));
            addr = INT2PTR(MIME__Fast__InternetAddress, tmp);
          } else
            croak("Usage: internet_address_set_group(InternetAddr, [InternetAddr]+");
          if (addr)
            g_list_append (addrlist, addr);
        }
        if (addrlist)
          internet_address_set_group(ia, addrlist);

void
internet_address_add_member(ia, member)
        MIME::Fast::InternetAddress	ia
        MIME::Fast::InternetAddress	member

MIME::Fast::InternetAddressType
internet_address_type(ia)
        MIME::Fast::InternetAddress	ia
    CODE:
        RETVAL = ia->type;
    OUTPUT:
        RETVAL

MODULE = MIME::Fast		PACKAGE = MIME::Fast::Charset		PREFIX=g_mime_charset_

void
g_mime_charset_init()

gchar *
g_mime_charset_locale_name()

MODULE = MIME::Fast		PACKAGE = MIME::Fast::DataWrapper	PREFIX=g_mime_data_wrapper_

MIME::Fast::DataWrapper
g_mime_data_wrapper_new(Class, mime_stream = 0, encoding = 0)
    CASE: items <= 1
    CODE:
    	RETVAL = g_mime_data_wrapper_new();
        plist = g_list_prepend(plist, RETVAL);
    OUTPUT:
    	RETVAL

    CASE: items == 3
        const gchar *		Class
        MIME::Fast::Stream	mime_stream
        MIME::Fast::PartEncodingType		encoding
    CODE:
    	RETVAL = g_mime_data_wrapper_new_with_stream(mime_stream, encoding);
        plist = g_list_prepend(plist, RETVAL);
    OUTPUT:
    	RETVAL

void
DESTROY(mime_data_wrapper)
        MIME::Fast::DataWrapper	mime_data_wrapper
    CODE:
        if (g_list_find(plist,mime_data_wrapper)) {
          g_mime_data_wrapper_destroy(mime_data_wrapper);
          plist = g_list_remove(plist, mime_data_wrapper);
        }

long
g_mime_data_wrapper_write_to_stream(mime_data_wrapper, mime_stream)
        MIME::Fast::DataWrapper	mime_data_wrapper
        MIME::Fast::Stream	mime_stream

void
g_mime_data_wrapper_set_stream(mime_data_wrapper, mime_stream)
        MIME::Fast::DataWrapper	mime_data_wrapper
        MIME::Fast::Stream	mime_stream

MIME::Fast::Stream
g_mime_data_wrapper_get_stream(mime_data_wrapper)
        MIME::Fast::DataWrapper	mime_data_wrapper
    CODE:
        RETVAL = g_mime_data_wrapper_get_stream(mime_data_wrapper);
        if (RETVAL)
          plist = g_list_prepend(plist, RETVAL);

void
g_mime_data_wrapper_set_encoding(mime_data_wrapper, encoding)
        MIME::Fast::DataWrapper		mime_data_wrapper
        MIME::Fast::PartEncodingType	encoding

MIME::Fast::PartEncodingType
g_mime_data_wrapper_get_encoding(mime_data_wrapper)
        MIME::Fast::DataWrapper		mime_data_wrapper

MODULE = MIME::Fast		PACKAGE = MIME::Fast::Stream		PREFIX=g_mime_stream_

 # partial support - TODO: maybe IO:: support

 #
 # Create Stream for string or FILE
 #

MIME::Fast::Stream
g_mime_stream_new(Class, svmixed = 0, start = 0, end = 0)
    CASE: items == 1
    CODE:
    	RETVAL = g_mime_stream_mem_new();
        plist = g_list_prepend(plist, RETVAL);
    OUTPUT:
    	RETVAL

    CASE: items == 2
        const gchar *	Class
        SV *		svmixed
    PREINIT:
        STRLEN		len;
        gchar *		data;
        GMimeStream	*mime_stream = NULL;
        svtype		svvaltype;
        SV *		svval;
    CODE:
    	svval = svmixed;
        if (SvROK(svmixed)) {
          svval = SvRV(svmixed);
        }
        svvaltype = SvTYPE(svval);

        if (mime_stream == NULL) {
          if (svvaltype == SVt_PVGV) { // possible FILE * handle
            FILE *  fp = IoIFP(sv_2io(svval));

            mime_stream = g_mime_stream_file_new(fp);
        ((GMimeStreamFile *)mime_stream)->owner = FALSE;
          } else if (SvPOK(svval)) {
            data = (gchar *)SvPV(svmixed, len);
            mime_stream = g_mime_stream_mem_new_with_buffer(data,len);
          } else {
            croak("stream_new: Unknown type: %d", (int)svvaltype);
          }
        }
    	RETVAL = mime_stream;
        plist = g_list_prepend(plist, RETVAL);
    OUTPUT:
        RETVAL
    
    CASE: items == 4
        const gchar *	Class
        SV *		svmixed
        off_t		start
        off_t		end
    PREINIT:
        STRLEN		len;
        gchar *		data;
        GMimeStream	*mime_stream = NULL;
        svtype		svvaltype;
        SV *		svval;
    CODE:
    	svval = svmixed;
        if (SvROK(svmixed)) {
          svval = SvRV(svmixed);
        }
        svvaltype = SvTYPE(svval);

        if (mime_stream == NULL) {
          if (svvaltype == SVt_PVGV) { // possible FILE * handle
            FILE *  fp = IoIFP(sv_2io(svval));

            mime_stream = g_mime_stream_file_new_with_bounds(fp, start, end);
        ((GMimeStreamFile *)mime_stream)->owner = FALSE;
          } else if (SvPOK(svval)) {
            warn ("stream_new: bounds for string are not supported");
          } else {
            croak("stream_new: Unknown type: %d", (int)svvaltype);
          }
        }
    	RETVAL = mime_stream;
        plist = g_list_prepend(plist, RETVAL);
    OUTPUT:
        RETVAL

void
DESTROY(mime_stream)
        MIME::Fast::Stream	mime_stream
    CODE:
        if (g_list_find(plist,mime_stream)) {
          g_mime_stream_unref(mime_stream);
          plist = g_list_remove(plist, mime_stream);
        }

MIME::Fast::Stream
g_mime_stream_substream(mime_stream, start, end)
        MIME::Fast::Stream	mime_stream
        off_t			start
        off_t			end
    CODE:
        RETVAL = g_mime_stream_substream(mime_stream, start, end);
        plist = g_list_prepend(plist, RETVAL);
    OUTPUT:
        RETVAL

void
g_mime_stream_set_bounds(mime_stream, start, end)
        MIME::Fast::Stream	mime_stream
        off_t			start
        off_t			end

long
g_mime_stream_write_string(mime_stream, str)
        MIME::Fast::Stream	mime_stream
        gchar *			str
    CODE:
        RETVAL = g_mime_stream_write_string(mime_stream, str);
    OUTPUT:
        RETVAL

long
g_mime_stream_length(mime_stream)
        MIME::Fast::Stream	mime_stream
    CODE:
        RETVAL = g_mime_stream_length(mime_stream);
    OUTPUT:
        RETVAL

long
g_mime_stream_write_to_stream(mime_stream_src, mime_stream_dst)
        MIME::Fast::Stream	mime_stream_src
        MIME::Fast::Stream	mime_stream_dst
    CODE:
        RETVAL = g_mime_stream_write_to_stream(mime_stream_src, mime_stream_dst);
    OUTPUT:
        RETVAL

MODULE = MIME::Fast		PACKAGE = MIME::Fast::Filter		PREFIX=g_mime_filter_

 # partial support - almost none

MIME::Fast::Filter
g_mime_filter_basic_new_type(type)
        int			type

MIME::Fast::Filter
g_mime_filter_crlf_new(direction, mode)
        int			direction
        int			mode

void
DESTROY(filter)
        MIME::Fast::Filter	filter
    CODE:
        g_mime_filter_destroy(filter);

MODULE = MIME::Fast		PACKAGE = MIME::Fast::Parser		PREFIX=g_mime_parser_

MIME::Fast::Message
g_mime_parser_construct_message(svmixed, preserve_headers = TRUE)
        SV *		svmixed
        gboolean	preserve_headers
    PREINIT:
        STRLEN		len;
        gchar *		data;
        GMimeMessage	*mime_msg = NULL;
        GMimeStream	*mime_stream = NULL;
        svtype		svvaltype;
        SV *		svval;
    CODE:
    	svval = svmixed;
        if (SvROK(svmixed)) {
          if (sv_derived_from(svmixed, "MIME::Fast::DataWrapper")) {
          	IV tmp = SvIV((SV*)SvRV(svmixed));
        	GMimeDataWrapper *mime_data_wrapper;

        	mime_data_wrapper = INT2PTR(MIME__Fast__DataWrapper,tmp);
        	mime_stream = g_mime_data_wrapper_get_stream(mime_data_wrapper);
          	mime_msg = g_mime_parser_construct_message(mime_stream, preserve_headers);
          } else if (sv_derived_from(svmixed, "MIME::Fast::Stream")) {
          	IV tmp = SvIV((SV*)SvRV(svmixed));

        	mime_stream = INT2PTR(MIME__Fast__Stream,tmp);
          	mime_msg = g_mime_parser_construct_message(mime_stream, preserve_headers);
          }
          svval = SvRV(svmixed);
        }
        svvaltype = SvTYPE(svval);

        if (mime_stream == NULL) {
          if (svvaltype == SVt_PVGV) { // possible FILE * handle
            FILE *  fp = IoIFP(sv_2io(svval));

            mime_stream = g_mime_stream_file_new(fp);
            ((GMimeStreamFile *)mime_stream)->owner = FALSE;
            mime_msg = g_mime_parser_construct_message(mime_stream, preserve_headers);
            g_mime_stream_unref(mime_stream);
          } else if (SvPOK(svval)) {
            data = (gchar *)SvPV(svval, len);
            mime_stream = g_mime_stream_mem_new_with_buffer(data,len);
            mime_msg = g_mime_parser_construct_message(mime_stream, preserve_headers);
            g_mime_stream_unref(mime_stream);
          } else {
            croak("construct_message: Unknown type: %d", (int)svvaltype);
          }
        }
    	
        RETVAL = mime_msg;
        plist = g_list_prepend(plist, RETVAL);
    OUTPUT:
        RETVAL

MIME::Fast::Part
g_mime_parser_construct_part(svmixed)
        SV *		svmixed
    PREINIT:
        STRLEN		len;
        gchar *		data;
        GMimePart	*mime_part = NULL;
        GMimeStream	*mime_stream = NULL;
        svtype		svvaltype;
        SV *		svval;
    CODE:
    	svval = svmixed;
        if (SvROK(svmixed)) {
          if (sv_derived_from(svmixed, "MIME::Fast::DataWrapper")) {
          	IV tmp = SvIV((SV*)SvRV(svmixed));
        	GMimeDataWrapper *mime_data_wrapper;

        	mime_data_wrapper = INT2PTR(MIME__Fast__DataWrapper,tmp);
        	mime_stream = g_mime_data_wrapper_get_stream(mime_data_wrapper);
          	mime_part = g_mime_parser_construct_part(mime_stream);
          } else if (sv_derived_from(svmixed, "MIME::Fast::Stream")) {
          	IV tmp = SvIV((SV*)SvRV(svmixed));

        	mime_stream = INT2PTR(MIME__Fast__Stream,tmp);
          	mime_part = g_mime_parser_construct_part(mime_stream);
          }
          svval = SvRV(svmixed);
        }
        svvaltype = SvTYPE(svval);

        if (mime_stream == NULL) {
          if (svvaltype == SVt_PVGV) { // possible FILE * handle
            FILE *  fp = IoIFP(sv_2io(svval));

            mime_stream = g_mime_stream_file_new(fp);
        ((GMimeStreamFile *)mime_stream)->owner = FALSE;
            mime_part = g_mime_parser_construct_part(mime_stream);
            g_mime_stream_unref(mime_stream);
          } else if (SvPOK(svval)) {
            data = (gchar *)SvPV(svmixed, len);
            mime_stream = g_mime_stream_mem_new_with_buffer(data,len);
            mime_part = g_mime_parser_construct_part(mime_stream);
            g_mime_stream_unref(mime_stream);
          } else {
            croak("construct_part: Unknown type: %d", (int)svvaltype);
          }
        }
    	
        RETVAL = mime_part;
        plist = g_list_prepend(plist, RETVAL);
    OUTPUT:
        RETVAL

MODULE = MIME::Fast		PACKAGE = MIME::Fast::Utils		PREFIX=g_mime_utils_

# date
time_t
g_mime_utils_header_decode_date(in, saveoffset)
        const gchar *	in
        gint 		&saveoffset
    OUTPUT:
        saveoffset

SV *
g_mime_utils_header_format_date(time, offset)
        time_t		time
        gint		offset
    PREINIT:
        gchar *		out = NULL;
    CODE:
        out = g_mime_utils_header_format_date(time, offset);
        if (out) {
          RETVAL = sv_2mortal(newSVpvn(out,0));
          g_free(out);
        } else
          RETVAL = &PL_sv_undef;
    OUTPUT:
        RETVAL
        

# headers
SV *
g_mime_utils_header_fold(in)
        const gchar *	in
    PREINIT:
        gchar *		out = NULL;
    CODE:
        out = g_mime_utils_header_fold(in);
        if (out) {
          RETVAL = sv_2mortal(newSVpvn(out,0));
          g_free(out);
        } else
          RETVAL = &PL_sv_undef;
    OUTPUT:
        RETVAL
        				    

# not implemented g_mime_utils_header_printf()

# quote
SV *
g_mime_utils_quote_string(in)
        const gchar *	in
    PREINIT:
        gchar *		out = NULL;
    CODE:
        out = g_mime_utils_quote_string(in);
        warn("In=%s Out=%s\n", in, out);
        if (out) {
          RETVAL = newSVpv(out,0);
          g_free(out);
        } else
          RETVAL = &PL_sv_undef;
    OUTPUT:
        RETVAL

void
g_mime_utils_unquote_string(str)
        gchar *		str
    OUTPUT:
        str

# encoding
gboolean
g_mime_utils_text_is_8bit(str)
        SV *		str
    PREINIT:
        char *	data;
        STRLEN	len;
    CODE:
        data = SvPV(str, len);
        RETVAL = g_mime_utils_text_is_8bit(data, len);
    OUTPUT:
        RETVAL

MIME::Fast::PartEncodingType
g_mime_utils_best_encoding(str)
        SV *		str
    PREINIT:
        char *	data;
        STRLEN	len;
    CODE:
        data = SvPV(str, len);
        RETVAL = g_mime_utils_best_encoding(data, len);
    OUTPUT:
        RETVAL

gchar *
g_mime_utils_8bit_header_decode(in)
        const guchar *	in

gchar *
g_mime_utils_8bit_header_encode(in)
        const guchar *	in

gchar *
g_mime_utils_8bit_header_encode_phrase(in)
        const guchar *	in

# not implemented - incremental base64:
#	g_mime_utils_base64_decode_step()
#	g_mime_utils_base64_encode_step()
#	g_mime_utils_base64_encode_close()
#gint
#g_mime_utils_base64_decode_step(in, out, state, save)
#	SV *		in
#	guchar *	out
#	gint		state
#	gint		&save
#    PREINIT:
#	char *	data;
#	STRLEN	len;
#    CODE:
#	data = SvPV(in, len);
#	RETVAL = g_mime_utils_base64_decode_step(data, len, state, save);
#    OUTPUT:
#	RETVAL
#	save

# not implemented:
# g_mime_utils_uudecode_step
# g_mime_utils_quoted_decode_step
# g_mime_utils_quoted_encode_step
# g_mime_utils_quoted_encode_close

MODULE = MIME::Fast		PACKAGE = MIME::Fast::Hash::Header		PREFIX=hash_

MIME::Fast::Hash::Header
hash_TIEHASH(Class, objptr)
        gchar *			Class
        MIME::Fast::Message		objptr
    PREINIT:
        hash_header *		hash;
    CODE:
        hash = g_malloc(sizeof(hash_header));
        hash->keyindex = 0;
        hash->objptr = objptr;
        if (gmime_debug)
        warn("function hash_TIEHASH(%s, 0x%x) returns 0x%x\n", Class, objptr, hash);
        RETVAL = hash;
    OUTPUT:
        RETVAL

void
hash_DESTROY(obj)
        MIME::Fast::Hash::Header	obj
    CODE:
        if (gmime_debug)
        warn("function hash_DESTROY(0x%x)\n", obj);
        obj->objptr = NULL;
        g_free(obj);

void
hash_FETCH(obj, key)
        MIME::Fast::Hash::Header	obj
        const gchar *		key
    PREINIT:
        MIME__Fast__Message		msg;
        gchar *			ret;
        GList			*gret = NULL, *item;
        AV *			retav;
        I32			gimme = GIMME_V;
    PPCODE:
        msg = obj->objptr;

        /* THE HACK - FETCH method would get value indirectly from NEXTKEY */
        if (obj->keyindex != -1 && obj->fetchvalue != NULL) {
          XPUSHs(sv_2mortal(newSVpv(obj->fetchvalue,0)));
          obj->fetchvalue == NULL;
          XSRETURN(1);
        }

        obj->fetchvalue = NULL;
        
        gret = message_get_header(msg, key);
        if (gmime_debug)
          warn("hash_FETCH(0x%x, '%s', items=%d)", obj, key ? key : "NULL", items);

        if (!gret || gret->data == NULL) {
          if (gmime_debug)
            warn("fetch returns undef\n");
          
          if (gret)
            g_list_free(gret);
          
          XSRETURN(0);
        } else {
          if (gret->next == NULL) { // one value
            XPUSHs(sv_2mortal(newSVpv((gchar *)(gret->data),0)));
          } else {
            if (gimme == G_ARRAY) {
              item = gret;
              while (item && item->data) {
                XPUSHs(sv_2mortal(newSVpv((gchar *)(item->data),0)));
                item = item->next;
              }
            } else if (gimme == G_SCALAR) {
              retav = newAV();
              item = gret;
              while (item && item->data) {
                av_push(retav, newSVpv((gchar *)g_strdup((item->data)), 0));
                item = item->next;
              }
              XPUSHs(newRV_noinc((SV *)retav));
            }
          }
        }
        if (gret) {
          item = gret;
          while (item) {
            if (item->data)
              g_free((gchar *)(item->data));
            item = item->next;
          }
          g_list_free(gret);
        }

void
hash_STORE(obj, key, svmixed)
        MIME::Fast::Hash::Header	obj
        const gchar *		key
        SV *			svmixed
    PREINIT:
        MIME__Fast__Message		msg;
        gchar *			value;
        AV *			avvalue;
        SV *			svvalue;
        svtype			svvaltype;
        STRLEN			vallen;
    CODE:
        /* only one value can be stored - no arrays allowed by perl */
        msg = obj->objptr;

        svvalue = svmixed;
        if (SvROK(svmixed)) {
          svvalue = SvRV(svmixed);
        }
        svvaltype = SvTYPE(svvalue);

        if (SvGMAGICAL(svvalue)) {
          if (gmime_debug)
            warn("hash_STORE: mg_get sv magical");
          mg_get(svvalue);
        }
        
        // TEST: display sv value
        if (gmime_debug)
          warn_type(svvalue, "hash_STORE");

        /* delete header for the first array item */
        message_remove_header(msg, key);

        if (svvaltype == SVt_PVAV) {
          AV *	avvalue;
          I32		i, avlen;
          SV *	svtmp;

          /* set header */
          avvalue = (AV *)svvalue;
          avlen = av_len(avvalue);
          for (i=0; i<=avlen; ++i) {
            svtmp = (SV *)(*(av_fetch(avvalue, i, 0)));

            if (SvGMAGICAL(svtmp)) {
              if (gmime_debug)
                warn("hash_STORE(AV): mg_get sv magical");
              mg_get(svtmp);
            }
            
            if (svtmp && SvPOKp(svtmp)) {
              value = (gchar *)SvPV(svtmp, vallen);
              message_set_header(msg, key, value);
            }
          }
        } else if (SvPOK(svvalue) || SvIOK(svvalue) || SvNOK(svvalue)) {
          value = (gchar *)SvPV(svvalue, vallen);
          message_set_header(msg, key, value);
        } else { /* assume scalar value */
          /* undefined value -> remove header */
          if (!(SvOK(svvalue)))
            message_remove_header(msg, key);
          else if (!(SvPOKp(svvalue)))
            croak("hash_STORE: Unknown sv type: %d for field %s 0x%x/0x%x/0x%x",
              SvTYPE(svvalue), key, &svvalue, &PL_sv_undef, svvalue);
        }
        if (gmime_debug)
          warn("hash_STORE: %s(0x%x) = %s\n", key, svvalue, SvPV(svvalue, vallen));

gboolean
hash_EXISTS(obj, key)
        MIME::Fast::Hash::Header	obj
        const gchar *		key
    PREINIT:
        MIME__Fast__Message		msg;
        gchar *			ret;
        GList			*gret, *item;
    CODE:
        msg = obj->objptr;
        if (gmime_debug)
         warn("hash_EXISTS(%s)\n", key);
        gret = message_get_header(msg, key);
        RETVAL = (gret != NULL && gret->data != NULL);
        if (gret) {
          item = gret;
          while (item) {
            if (item->data)
              g_free((gchar *)(item->data));
            item = item->next;
          }
          g_list_free(gret);
        }
    OUTPUT:
        RETVAL

void
hash_DELETE(obj, key)
        MIME::Fast::Hash::Header	obj
        const gchar *		key
    CODE:
        if (gmime_debug)
        warn("hash_DELETE %s\n", key);
        message_remove_header((MIME__Fast__Message) obj->objptr, key);

void
hash_NEXTKEY(obj, lastkey = NULL)
        MIME::Fast::Hash::Header	obj
        const gchar *		lastkey
    ALIAS:
        MIME::Fast::Hash::Header::FIRSTKEY = 1
    PREINIT:
        gchar *			key = NULL;
        gchar *			value = NULL;
        MIME__Fast__Message		msg;
        I32			gimme = GIMME_V;
        gint			i, j, found;
        local_GMimeHeader *		header;
        struct raw_header	*h;
    INIT:
        if (ix == 1) {
          obj->keyindex = -1;
        }
    PPCODE:
        msg = obj->objptr;
        ++obj->keyindex;
        if (gmime_debug)
          warn("hash_NEXTKEY");
        i = obj->keyindex;
        header = msg->header->headers;

        h = header->headers;
        j = 0;
        found = 0;
        while (h) {
          if (j >= i) {
            key = h->name;
            value = h->value;
            found = 1;
            break;
          }
          j++;
          h = h->next;
        }
        
        if (!found && key == NULL) {
          obj->keyindex = -1;
        }

        if (gimme != G_SCALAR && !value) {
          // TODO: does each, keys, retrieves the value?
          // retrieve the value
          warn("Error: NEED TO RETRIEVE THE VALUE, contact the author\n");
        }
        
        /* THE HACK - FETCH method would get value indirectly */
        obj->fetchvalue = NULL;

        if (key) {
          XPUSHs(sv_2mortal(newSVpv(key,0)));
          if (gimme != G_SCALAR && value)
            XPUSHs(sv_2mortal(newSVpv(value,0)));
          /* THE HACK - FETCH method would get value indirectly */
          obj->fetchvalue = value;
        }
        if (gmime_debug)
          warn("hash_%s(0x%x, %s) = (\"%s\",\"%s\") key no. %d%s",
        	(ix == 1) ? "FIRSTKEY" : "NEXTKEY",
        	obj, lastkey ? lastkey : "NULL",
        	key ? key : "NULL",
        	value ? value : "NULL",
        	i, obj->keyindex == -1 ? " (last)" : "");



void
hash_CLEAR(obj)
        MIME::Fast::Hash::Header	obj
    PREINIT:
        MIME__Fast__Message		message;
        gint			i;
        local_GMimeHeader		*header;
        struct raw_header	*h;
    CODE:
        message = obj->objptr;
        if (gmime_debug)
        warn("function hash_CLEAR(0x%x)\n", obj);
        
        g_free (message->header->from);
        message->header->from = NULL;

        g_free (message->header->reply_to);
        message->header->reply_to = NULL;
        
        /* destroy all recipients */
        g_hash_table_foreach_remove (message->header->recipients, recipients_destroy, NULL);
        //g_hash_table_destroy (message->header->recipients);
        //message->header->recipients = g_hash_table_new (g_str_hash, g_str_equal);	
        
        g_free (message->header->subject);
        message->header->subject = NULL;
        
        g_free (message->header->message_id);
        message->header->message_id = NULL;

        /* free all the headers */
        header = message->header->headers;
        g_mime_header_destroy(header);
        message->header->headers = g_mime_header_new ();

