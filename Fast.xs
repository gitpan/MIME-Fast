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
#include "gmime-version.h"

#define XSINTERFACE_FUNC_MIMEFAST_MESSAGE_SET(cv,f)      \
	CvXSUBANY(cv).any_dptr = (void (*) (pTHX_ void*))(CAT2( g_mime_message_,f ))
#define XSINTERFACE_FUNC_MIMEFAST_PART_SET(cv,f)      \
	CvXSUBANY(cv).any_dptr = (void (*) (pTHX_ void*))(CAT2( g_mime_part_,f ))
#define XSINTERFACE_FUNC_MIMEFAST_MULTIPART_SET(cv,f)      \
	CvXSUBANY(cv).any_dptr = (void (*) (pTHX_ void*))(CAT2( g_mime_multipart_,f ))
#define XSINTERFACE_FUNC_MIMEFAST_IA_SET(cv,f)      \
	CvXSUBANY(cv).any_dptr = (void (*) (pTHX_ void*))(CAT2( internet_address_,f ))
	
/* debug output from MIME::Fast module */
static gboolean gmime_debug = 0;

struct raw_header {
    struct raw_header *next;
    char *name;
    char *value;
};			

typedef struct _GMimeHeader {
        GHashTable *hash;
	GHashTable *writers;
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
warn_type(SV *svmixed, char *text)
{
  SV		*svval;
  svtype	svvaltype;
  char		*svtext;
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
        case 'B':
	  /* gmime-filter-best.h */
          if (strEQ(name, "GMIME_BEST_ENCODING_7BIT"))
            return GMIME_BEST_ENCODING_7BIT;
          else if (strEQ(name, "GMIME_BEST_ENCODING_8BIT"))
            return GMIME_BEST_ENCODING_8BIT;
          else if (strEQ(name, "GMIME_BEST_ENCODING_BINARY"))
            return GMIME_BEST_ENCODING_BINARY;
	  break;
        case 'C':
	  /* gmime-cipher-context.h */
          if (strEQ(name, "GMIME_CIPHER_HASH_DEFAULT"))
            return GMIME_CIPHER_HASH_DEFAULT;
          else if (strEQ(name, "GMIME_CIPHER_HASH_MD2"))
            return GMIME_CIPHER_HASH_MD2;
          else if (strEQ(name, "GMIME_CIPHER_HASH_MD5"))
            return GMIME_CIPHER_HASH_MD5;
          else if (strEQ(name, "GMIME_CIPHER_HASH_SHA1"))
            return GMIME_CIPHER_HASH_SHA1;
          else if (strEQ(name, "GMIME_CIPHER_HASH_RIPEMD160"))
            return GMIME_CIPHER_HASH_RIPEMD160;
          else if (strEQ(name, "GMIME_CIPHER_HASH_TIGER192"))
            return GMIME_CIPHER_HASH_TIGER192;
          else if (strEQ(name, "GMIME_CIPHER_HASH_HAVAL5160"))
            return GMIME_CIPHER_HASH_HAVAL5160;
	  break;
        case 'E':
	  /* gmime-error.h */
          if (strEQ(name, "GMIME_ERROR_GENERAL"))
            return GMIME_ERROR_GENERAL;
          else if (strEQ(name, "GMIME_ERROR_NOT_SUPPORTED"))
            return GMIME_ERROR_NOT_SUPPORTED;
          else if (strEQ(name, "GMIME_ERROR_PARSE_ERROR"))
            return GMIME_ERROR_PARSE_ERROR;
          else if (strEQ(name, "GMIME_ERROR_PROTOCOL_ERROR"))
            return GMIME_ERROR_PROTOCOL_ERROR;
          else if (strEQ(name, "GMIME_ERROR_BAD_PASSWORD"))
            return GMIME_ERROR_BAD_PASSWORD;
          else if (strEQ(name, "GMIME_ERROR_NO_VALID_RECIPIENTS"))
            return GMIME_ERROR_NO_VALID_RECIPIENTS;
	  break;
        case 'F':
	  /* gmime-filter-basic.h */
          if (strEQ(name, "GMIME_FILTER_BASIC_BASE64_ENC"))
            return GMIME_FILTER_BASIC_BASE64_ENC;
          else if (strEQ(name, "GMIME_FILTER_BASIC_BASE64_DEC"))
            return GMIME_FILTER_BASIC_BASE64_DEC;
          else if (strEQ(name, "GMIME_FILTER_BASIC_QP_ENC"))
            return GMIME_FILTER_BASIC_QP_ENC;
          else if (strEQ(name, "GMIME_FILTER_BASIC_QP_DEC"))
            return GMIME_FILTER_BASIC_QP_DEC;
          else if (strEQ(name, "GMIME_FILTER_BASIC_UU_ENC"))
            return GMIME_FILTER_BASIC_UU_ENC;
          else if (strEQ(name, "GMIME_FILTER_BASIC_UU_DEC"))
            return GMIME_FILTER_BASIC_UU_DEC;
	  /* gmime-filter-best.h */
          else if (strEQ(name, "GMIME_FILTER_BEST_CHARSET"))
            return GMIME_FILTER_BEST_CHARSET;
          else if (strEQ(name, "GMIME_FILTER_BEST_ENCODING"))
            return GMIME_FILTER_BEST_ENCODING;
	  /* gmime-filter-crlf.h */
          else if (strEQ(name, "GMIME_FILTER_CRLF_ENCODE"))
            return GMIME_FILTER_CRLF_ENCODE;
          else if (strEQ(name, "GMIME_FILTER_CRLF_DECODE"))
            return GMIME_FILTER_CRLF_DECODE;
          else if (strEQ(name, "GMIME_FILTER_CRLF_MODE_CRLF_DOTS"))
            return GMIME_FILTER_CRLF_MODE_CRLF_DOTS;
          else if (strEQ(name, "GMIME_FILTER_CRLF_MODE_CRLF_ONLY"))
            return GMIME_FILTER_CRLF_MODE_CRLF_ONLY;
	  /* gmime-filter-from.h */
          else if (strEQ(name, "GMIME_FILTER_FROM_MODE_DEFAULT"))
            return GMIME_FILTER_FROM_MODE_DEFAULT;
          else if (strEQ(name, "GMIME_FILTER_FROM_MODE_ESCAPE"))
            return GMIME_FILTER_FROM_MODE_ESCAPE;
          else if (strEQ(name, "GMIME_FILTER_FROM_MODE_ARMOR"))
            return GMIME_FILTER_FROM_MODE_ARMOR;
	  /* gmime-filter-yenc.h */
          else if (strEQ(name, "GMIME_FILTER_YENC_DIRECTION_ENCODE"))
            return GMIME_FILTER_YENC_DIRECTION_ENCODE;
          else if (strEQ(name, "GMIME_FILTER_YENC_DIRECTION_DECODE"))
            return GMIME_FILTER_YENC_DIRECTION_DECODE;
	  break;
        case 'L':
	  /* local constants */
          if (strEQ(name, "GMIME_LENGTH_ENCODED"))
            return GMIME_LENGTH_ENCODED;
          else if (strEQ(name, "GMIME_LENGTH_CUMULATIVE"))
            return GMIME_LENGTH_CUMULATIVE;
          break;
        case 'M':
	  /* gmime-multipart-signed.h */
          if (strEQ(name, "GMIME_MULTIPART_SIGNED_CONTENT"))
            return GMIME_MULTIPART_SIGNED_CONTENT;
          else if (strEQ(name, "GMIME_MULTIPART_SIGNED_SIGNATURE"))
            return GMIME_MULTIPART_SIGNED_SIGNATURE;
	  /* gmime-multipart-encrypted.h */
          else if (strEQ(name, "GMIME_MULTIPART_ENCRYPTED_VERSION"))
            return GMIME_MULTIPART_ENCRYPTED_VERSION;
          else if (strEQ(name, "GMIME_MULTIPART_ENCRYPTED_CONTENT"))
            return GMIME_MULTIPART_ENCRYPTED_CONTENT;
	  break;
        case 'P':
	  /* gmime-utils.h */
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
          else if (strEQ(name, "GMIME_PART_ENCODING_UUENCODE"))
            return GMIME_PART_ENCODING_UUENCODE;
          else if (strEQ(name, "GMIME_PART_NUM_ENCODINGS"))
            return GMIME_PART_NUM_ENCODINGS;
          break;
        case 'S':
	  /* gmime-stream*.h */
          if (strEQ(name, "GMIME_STREAM_SEEK_SET"))
            return GMIME_STREAM_SEEK_SET;
          else if (strEQ(name, "GMIME_STREAM_SEEK_CUR"))
	    return GMIME_STREAM_SEEK_CUR;
          else if (strEQ(name, "GMIME_STREAM_SEEK_END"))
	    return GMIME_STREAM_SEEK_END;
          else if (strEQ(name, "GMIME_STREAM_BUFFER_CACHE_READ"))
	    return GMIME_STREAM_BUFFER_CACHE_READ;
          else if (strEQ(name, "GMIME_STREAM_BUFFER_BLOCK_READ"))
	    return GMIME_STREAM_BUFFER_BLOCK_READ;
          else if (strEQ(name, "GMIME_STREAM_BUFFER_BLOCK_WRITE"))
	    return GMIME_STREAM_BUFFER_BLOCK_WRITE;
          break;
        }
      }
      break;
    case 'I':
      /* internet-address.h */
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


static const char *
constant_string(char *name, int len, int arg)
{
    errno = 0;
    switch (*name) {
    case 'G':
      if (strnEQ(name, "GMIME_", 6)) {
        switch (*(name+6)) {
        case 'D':
	  /* gmime-disposition.h */
          if (strEQ(name, "GMIME_DISPOSITION_ATTACHMENT"))
            return GMIME_DISPOSITION_ATTACHMENT;
	  else if (strEQ(name, "GMIME_DISPOSITION_INLINE"))
	    return GMIME_DISPOSITION_INLINE;
#if GMIME_CHECK_VERSION_2_0_9
	  /* gmime-message-delivery.h */
          if (strEQ(name, "GMIME_DSN_ACTION_FAILED"))
            return GMIME_DSN_ACTION_FAILED;
          else if (strEQ(name, "GMIME_DSN_ACTION_DELAYED"))
            return GMIME_DSN_ACTION_DELAYED;
          else if (strEQ(name, "GMIME_DSN_ACTION_DELIVERED"))
            return GMIME_DSN_ACTION_DELIVERED;
          else if (strEQ(name, "GMIME_DSN_ACTION_RELAYED"))
            return GMIME_DSN_ACTION_RELAYED;
          else if (strEQ(name, "GMIME_DSN_ACTION_EXPANDED"))
            return GMIME_DSN_ACTION_EXPANDED;
#endif
	  break;
        case 'M':
#if GMIME_CHECK_VERSION_2_0_9
	  /* gmime-message-mdn-disposition.h */
          if (strEQ(name, "GMIME_MDN_DISPOSITION_DISPLAYED"))
            return GMIME_MDN_DISPOSITION_DISPLAYED;
          else
          if (strEQ(name, "GMIME_MDN_DISPOSITION_DISPATCHED"))
            return GMIME_MDN_DISPOSITION_DISPATCHED;
          else
          if (strEQ(name, "GMIME_MDN_DISPOSITION_PROCESSED"))
            return GMIME_MDN_DISPOSITION_PROCESSED;
          else
          if (strEQ(name, "GMIME_MDN_DISPOSITION_DELETED"))
            return GMIME_MDN_DISPOSITION_DELETED;
          else
          if (strEQ(name, "GMIME_MDN_DISPOSITION_DENIED"))
            return GMIME_MDN_DISPOSITION_DENIED;
          else
          if (strEQ(name, "GMIME_MDN_DISPOSITION_FAILED"))
            return GMIME_MDN_DISPOSITION_FAILED;
          else
          if (strEQ(name, "GMIME_MDN_ACTION_MANUAL"))
            return GMIME_MDN_ACTION_MANUAL;
          else
          if (strEQ(name, "GMIME_MDN_ACTION_AUTOMATIC"))
            return GMIME_MDN_ACTION_AUTOMATIC;
          else
          if (strEQ(name, "GMIME_MDN_SENT_MANUALLY"))
            return GMIME_MDN_SENT_MANUALLY;
          else
          if (strEQ(name, "GMIME_MDN_SENT_AUTOMATICALLY"))
            return GMIME_MDN_SENT_AUTOMATICALLY;
          else
          if (strEQ(name, "GMIME_MDN_MODIFIER_ERROR"))
            return GMIME_MDN_MODIFIER_ERROR;
          else
          if (strEQ(name, "GMIME_MDN_MODIFIER_WARNING"))
            return GMIME_MDN_MODIFIER_WARNING;
          else
          if (strEQ(name, "GMIME_MDN_MODIFIER_SUPERSEDED"))
            return GMIME_MDN_MODIFIER_SUPERSEDED;
          else
          if (strEQ(name, "GMIME_MDN_MODIFIER_EXPIRED"))
            return GMIME_MDN_MODIFIER_EXPIRED;
          else
          if (strEQ(name, "GMIME_MDN_MODIFIER_MAILBOX_TERMINATED"))
            return GMIME_MDN_MODIFIER_MAILBOX_TERMINATED;
#endif
          break;
        }
      }
      break;
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
typedef GMimeBestEncoding	MIME__Fast__BestEncoding;
typedef GMimeFilterFromMode	MIME__Fast__FilterFromMode;
typedef GMimeFilterYencDirection	Mime__Fast__FilterYencDirection;


/* C types */
typedef GMimeObject *		MIME__Fast__Object;
typedef GMimeParam *		MIME__Fast__Param;
typedef GMimePart *		MIME__Fast__Part;
typedef GMimeParser *		MIME__Fast__Parser;
typedef GMimeMultipart *	MIME__Fast__MultiPart;
typedef GMimeMessage *		MIME__Fast__Message;
typedef GMimeMessagePart *	MIME__Fast__MessagePart;
typedef GMimeMessagePartial *	MIME__Fast__MessagePartial;
#if GMIME_CHECK_VERSION_2_0_9
typedef GMimeMessageDelivery *	MIME__Fast__MessageDelivery;
typedef GMimeMessageMDN *	MIME__Fast__MessageMDN;
typedef GMimeMessageMDNDisposition *	MIME__Fast__MessageMDNDisposition;
typedef GMimeFilterFunc *	MIME__Fast__Filter__Func;
#endif
typedef InternetAddress *	MIME__Fast__InternetAddress;
typedef GMimeDisposition *	MIME__Fast__Disposition;
typedef GMimeContentType *	MIME__Fast__ContentType;
typedef GMimeStream *		MIME__Fast__Stream;
typedef GMimeStreamFilter *	MIME__Fast__StreamFilter;
typedef GMimeDataWrapper *	MIME__Fast__DataWrapper;
typedef GMimeFilter *		MIME__Fast__Filter;
typedef GMimeFilterBasic *	MIME__Fast__Filter__Basic;
typedef GMimeFilterBest *	MIME__Fast__Filter__Best;
typedef GMimeFilterCharset *	MIME__Fast__Filter__Charset;
typedef GMimeFilterCRLF *	MIME__Fast__Filter__CRLF;
typedef GMimeFilterFrom *	MIME__Fast__Filter__From;
typedef GMimeFilterHTML *	MIME__Fast__Filter__HTML;
typedef GMimeFilterMd5 *	MIME__Fast__Filter__Md5;
typedef GMimeFilterStrip *	MIME__Fast__Filter__Strip;
typedef GMimeFilterYenc *	MIME__Fast__Filter__Yenc;
typedef GMimeCharset *		MIME__Fast__Charset;

/*
 * Declarations for message header hash array
 */
#include "gmime-newfunc.c"
#include "gmime-newfuncheader.c"

#if GMIME_CHECK_VERSION_2_0_8
static void
local_mime_stream_file_set_owner (GMimeStream *stream, gboolean owner)
{
	GMimeStreamFile *fstream = GMIME_STREAM_FILE (stream);

	fstream->owner = owner;
}

static void
local_mime_stream_fs_set_owner (GMimeStream *stream, gboolean owner)
{
	GMimeStreamFs *fstream = GMIME_STREAM_FS (stream);

	fstream->owner = owner;
}
#define g_mime_stream_file_set_owner(s,o) local_mime_stream_file_set_owner(s,o)
#define g_mime_stream_fs_set_owner(s,o) local_mime_stream_fs_set_owner(s,o)
#endif

static gboolean
recipients_destroy (gpointer key, gpointer value, gpointer user_data)
{
        GList *recipients = value;
        
        if (recipients) {
        	GList *recipient;
        	
        	recipient = recipients;
        	while (recipient) {
        		internet_address_unref (recipient->data);
        		recipient = recipient->next;
        	}
        	
        	g_list_free (recipients);
        }
        
        return TRUE;
}


typedef struct {
        int			keyindex;	/* key index for firstkey */
        char			*fetchvalue;	/* value for each() method fetched with FETCH */
        MIME__Fast__Message	objptr;		/* any object pointer */
} hash_header;

typedef hash_header *	MIME__Fast__Hash__Header;

//const char *g_mime_message_get_sender (GMimeMessage *message);

/*
 * Double linked list of perl allocated pointers (for DESTROY xsubs)
 */
static GList *plist = NULL;

/*
 * Calling callback function for each mime part
 */
struct _user_data_sv {
    SV *  svfunc;
    SV *  svuser_data;
    SV *  svfunc_complete;
    SV *  svfunc_sizeout;
};

static void
call_sub_foreach(GMimeObject *mime_object, gpointer data)
{
    SV * svpart;
    SV * rvpart;
    HV * stash;

    dSP ;
    struct _user_data_sv *svdata;

    svdata = (struct _user_data_sv *) data;
    svpart = sv_newmortal();

    if (GMIME_IS_MESSAGE_PARTIAL(mime_object))
        rvpart = sv_setref_pv(svpart, "MIME::Fast::MessagePartial", (MIME__Fast__MessagePartial)mime_object);
#if GMIME_CHECK_VERSION_2_0_9
    else if (GMIME_IS_MESSAGE_MDN(mime_object))
        rvpart = sv_setref_pv(svpart, "MIME::Fast::MessageMDN", (MIME__Fast__MessageMDN)mime_object);
    else if (GMIME_IS_MESSAGE_DELIVERY(mime_object))
        rvpart = sv_setref_pv(svpart, "MIME::Fast::MessageDelivery", (MIME__Fast__MessageDelivery)mime_object);
#endif
    else if (GMIME_IS_MESSAGE_PART(mime_object))
        rvpart = sv_setref_pv(svpart, "MIME::Fast::MessagePart", (MIME__Fast__MessagePart)mime_object);
    else if (GMIME_IS_MULTIPART(mime_object))
        rvpart = sv_setref_pv(svpart, "MIME::Fast::MultiPart", (MIME__Fast__MultiPart)mime_object);
    else if (GMIME_IS_PART(mime_object))
        rvpart = sv_setref_pv(svpart, "MIME::Fast::Part", (MIME__Fast__Part)mime_object);
    else
        rvpart = sv_setref_pv(svpart, "MIME::Fast::Object", mime_object);
        
    if (gmime_debug)
      warn("function call_sub_foreach: setref (not in plist) MIME::Fast object 0x%x", mime_object);
    PUSHMARK(sp);
    XPUSHs(rvpart);
    XPUSHs(sv_mortalcopy(svdata->svuser_data));
    PUTBACK ;
    if (svdata->svfunc)
      perl_call_sv(svdata->svfunc, G_DISCARD);
}

/* filter sizeout func */
size_t
call_filter_sizeout_func (size_t len, gpointer data)
{
    dSP ;
    	int	count;
	size_t	outlen = 0;
        struct _user_data_sv *svdata;
	char *outptr;
	SV *	svin;

    ENTER ;
    SAVETMPS;

        svdata = (struct _user_data_sv *) data;

    PUSHMARK(sp);
	XPUSHs(sv_2mortal(newSViv(len)));
	if (svdata->svuser_data)
	XPUSHs(svdata->svuser_data);
    PUTBACK ;
    
        if (svdata->svfunc_sizeout)
          count = perl_call_sv(svdata->svfunc_sizeout, G_SCALAR);

    SPAGAIN ;

	switch (count) {
	    case 1:
		outlen = POPi;
		break;
	}
    PUTBACK ;
    FREETMPS ;
    LEAVE ;
	return outlen;
}


/* filter complete func */
size_t
call_filter_complete_func (unsigned char *in, size_t len, unsigned char *out, int *state, guint32 *save, gpointer data)
{
    dSP ;
    	int	count;
	size_t	outlen = 0;
        struct _user_data_sv *svdata;
	char *outptr;
	SV *	svin;

    ENTER ;
    SAVETMPS;

        svdata = (struct _user_data_sv *) data;

	svin = sv_newmortal();
	SvUPGRADE (svin, SVt_PV);
	SvREADONLY_on (svin);
	SvPVX (svin) = (char *)in;
	SvCUR_set (svin, len);
	SvLEN_set (svin, 0);
	SvPOK_only (svin);
	
    PUSHMARK(sp);
	XPUSHs(svin);
	XPUSHs(sv_2mortal(newSViv(*state)));
	XPUSHs(sv_2mortal(newSViv(*save)));
	if (svdata->svuser_data)
	XPUSHs(svdata->svuser_data);
    PUTBACK ;
    
        if (svdata->svfunc_complete)
          count = perl_call_sv(svdata->svfunc_complete, G_ARRAY);

    SPAGAIN ;

	switch (count) {
	    case 3:
		*save  = POPi;
	    case 2:
		*state = POPi;
	    case 1:
		{
		    STRLEN n_a;
		    outptr = POPpx;
		    outlen = n_a;
		    if (out && outptr && outlen > 0) {
			memcpy (out, outptr, outlen);
		    }
		}
		break;
	}
    PUTBACK ;
    FREETMPS ;
    LEAVE ;
	g_free (svdata);

	return outlen;
}



/* filter step func */
size_t
call_filter_step_func (unsigned char *in, size_t len, unsigned char *out, int *state, guint32 *save, gpointer data)
{
    dSP ;
    	int	count;
	size_t	outlen = 0;
        struct _user_data_sv *svdata;
	char *outptr;
	SV *	svin;

    ENTER ;
    SAVETMPS;

        svdata = (struct _user_data_sv *) data;

	svin = sv_newmortal();
	SvUPGRADE (svin, SVt_PV);
	SvREADONLY_on (svin);
	SvPVX (svin) = (char *)in;
	SvCUR_set (svin, len);
	SvLEN_set (svin, 0);
	SvPOK_only (svin);
	
    PUSHMARK(sp);
	XPUSHs(svin);
	XPUSHs(sv_2mortal(newSViv(*state)));
	XPUSHs(sv_2mortal(newSViv(*save)));
	if (svdata->svuser_data)
	XPUSHs(svdata->svuser_data);
    PUTBACK ;
    
        if (svdata->svfunc)
          count = perl_call_sv(svdata->svfunc, G_ARRAY);

    SPAGAIN ;

	switch (count) {
	    case 3:
		*save  = POPi;
	    case 2:
		*state = POPi;
	    case 1:
		{
		    STRLEN n_a;
		    outptr = POPpx;
		    outlen = n_a;
		    if (out && outptr && outlen > 0) {
			memcpy (out, outptr, outlen);
		    }
		}
		break;
	}
    PUTBACK ;
    FREETMPS ;
    LEAVE ;

	return outlen;
}


/*
 * Returns content length of the given mime part and its descendants
 */
static guint
get_content_length(GMimeObject *mime_object, int method)
{
        guint			lsize = 0;
	GMimePart *		mime_part;
	GMimeMultipart *	mime_multipart;

        if (mime_object) {
		if (GMIME_IS_MULTIPART(mime_object)) {
		    mime_multipart = GMIME_MULTIPART(mime_object);
        	    if ((method & GMIME_LENGTH_CUMULATIVE)) {
        		GList *child = GMIME_MULTIPART (mime_multipart)->subparts;
        		while (child) {
        			lsize += get_content_length ( GMIME_OBJECT(child->data), method );
        			child = child->next;
        		}
        	    }
		} else if (GMIME_IS_PART(mime_object)) { // also MESSAGE_PARTIAL
		    mime_part = GMIME_PART(mime_object);
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
		} else if (GMIME_IS_MESSAGE_PART(mime_object)) {
		    lsize += get_content_length(GMIME_OBJECT((g_mime_message_part_get_message(GMIME_MESSAGE_PART(mime_object)))), method);
		} else if (GMIME_IS_MESSAGE(mime_object)) {
		    if (GMIME_MESSAGE(mime_object)->mime_part != NULL)
        	        lsize += get_content_length ( GMIME_OBJECT(GMIME_MESSAGE(mime_object)->mime_part), method );
		}
        }
        return lsize;
}

MODULE = MIME::Fast		PACKAGE = MIME::Fast		

SV *
get_object_type(svmixed)
        SV *		        svmixed
    PREINIT:
        void *	data = NULL;
        SV*     svval;
        svtype	svvaltype;
        SV *	content;
        guint	len;
        const char * content_char;
    CODE:
    	svval = svmixed;
        svvaltype = SvTYPE(svval);
	if (!sv_isobject(svmixed))
	  XSRETURN_UNDEF;
        if (SvROK(svmixed)) {
          IV tmp;
          svval = SvRV(svmixed);
          tmp = SvIV(svval);
	  data = (void *)tmp;
	} else {
	  XSRETURN_UNDEF;
	}
        if (data == NULL) {
	    XSRETURN_UNDEF;
#if GMIME_CHECK_VERSION_2_0_9
	} else if (GMIME_IS_MESSAGE_MDN((GMimeMessageMDN *)data)) {
	    RETVAL = newSVpv("MIME::Fast::MessageMDN", 0); 
	} else if (GMIME_IS_MESSAGE_DELIVERY((GMimeMessageDelivery *)data)) {
	    RETVAL = newSVpv("MIME::Fast::MessageDelivery", 0); 
#endif
	} else if (GMIME_IS_MESSAGE_PARTIAL((GMimeMessagePartial *)data)) {
	    RETVAL = newSVpv("MIME::Fast::MessagePartial", 0); 
	} else if (GMIME_IS_PART((GMimePart *)data)) {
	    RETVAL = newSVpv("MIME::Fast::Part", 0); 
	} else if (GMIME_IS_MULTIPART((GMimeMultipart *)data)) {
	    RETVAL = newSVpv("MIME::Fast::MultiPart", 0); 
	} else if (GMIME_IS_MESSAGE((GMimeMessage *)data)) {
	    RETVAL = newSVpv("MIME::Fast::Message", 0); 
	} else if (GMIME_IS_MESSAGE_PART((GMimeMessagePart *)data)) {
	    RETVAL = newSVpv("MIME::Fast::MessagePart", 0); 
	} else if (GMIME_IS_OBJECT((GMimeObject *)data)) {
	    RETVAL = newSVpv("MIME::Fast::Object", 0); 
	} else if (sv_isobject(svmixed)) {
            RETVAL = newSVpv( HvNAME( SvSTASH(SvRV(svmixed)) ), 0);
	} else {
            XSRETURN_UNDEF;
	}
    OUTPUT:
    	RETVAL
	

BOOT:
g_mime_init(0);

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

const char *
constant_string(sv,arg)
    PREINIT:
        STRLEN		len;
    INPUT:
        SV *		sv
        char *		s = SvPV(sv, len);
        int		arg
    CODE:
        RETVAL = constant_string(s,len,arg);
    OUTPUT:
        RETVAL

MODULE = MIME::Fast		PACKAGE = MIME::Fast::Object		PREFIX=g_mime_object_

 # unsupported:
 #  g_mime_object_register_type
 #  g_mime_object_new_type
 #  g_mime_object_ref
 #  g_mime_object_unref

 #
 # content_type
 #
void
g_mime_object_set_content_type(mime_object, content_type)
        MIME::Fast::Object	mime_object
        MIME::Fast::ContentType	content_type
    CODE:
        g_mime_object_set_content_type(mime_object, content_type);
        plist = g_list_remove(plist, content_type);

MIME::Fast::ContentType
g_mime_object_get_content_type(mime_object)
        MIME::Fast::Object	mime_object
    PREINIT:
	char *			textdata;
	const GMimeContentType	*ct;
    CODE:
	ct = g_mime_object_get_content_type(mime_object);
	textdata = g_mime_content_type_to_string(ct);
        RETVAL = g_mime_content_type_new_from_string(textdata);
	plist = g_list_prepend(plist, RETVAL);
	g_free (textdata);
    OUTPUT:
    	RETVAL

 #
 # content_type_parameter
 #
void
g_mime_object_set_content_type_parameter(mime_object, name, value)
        MIME::Fast::Object	mime_object
	const char *		name
	const char *		value

const char *
g_mime_object_get_content_type_parameter(mime_object, name)
        MIME::Fast::Object	mime_object
	const char *		name

 #
 # content_id
 #
void
g_mime_object_set_content_id(mime_object, content_id)
        MIME::Fast::Object	mime_object
	const char *		content_id

const char *
g_mime_object_get_content_id(mime_object)
        MIME::Fast::Object	mime_object

 #
 # header
 #
void
g_mime_object_add_header(mime_object, field, value)
        MIME::Fast::Object	mime_object
        const char *	field
        const char *	value

void
g_mime_object_set_header(mime_object, field, value)
        MIME::Fast::Object	mime_object
        const char *	field
        const char *	value

const char *
g_mime_object_get_header(mime_object, field)
        MIME::Fast::Object	mime_object
        const char *	field

void
g_mime_object_remove_header(mime_object, field)
        MIME::Fast::Object	mime_object
        const char *	field

SV *
g_mime_object_get_headers(mime_object)
        MIME::Fast::Object	mime_object
    PREINIT:
	char *		textdata;
    CODE:
	textdata = g_mime_object_get_headers(mime_object);
	if (textdata == NULL)
	  XSRETURN_UNDEF;
        RETVAL = newSVpv(textdata, 0);
	g_free (textdata);
    OUTPUT:
        RETVAL

ssize_t
g_mime_object_write_to_stream(mime_object, mime_stream)
        MIME::Fast::Object	mime_object
	MIME::Fast::Stream		mime_stream
    CODE:
	RETVAL = g_mime_object_write_to_stream (mime_object, mime_stream);
    OUTPUT:
	RETVAL

SV *
g_mime_object_to_string(mime_object)
        MIME::Fast::Object	mime_object
    PREINIT:
	char *	textdata;
    CODE:
	textdata = g_mime_object_to_string (mime_object);
	if (textdata) {
	  RETVAL = newSVpv(textdata, 0);
	  g_free (textdata);
	} else {
	  XSRETURN_UNDEF;
	}
    OUTPUT:
	RETVAL





MODULE = MIME::Fast		PACKAGE = MIME::Fast::Param		PREFIX=g_mime_param_

MIME::Fast::Param
g_mime_param_new(Class = "MIME::Fast::Param", name = 0, value = 0)
    CASE: items == 2
        char *		Class;
        const char *	name;
    CODE:
        RETVAL = g_mime_param_new_from_string(name);
        plist = g_list_prepend(plist, RETVAL);
    OUTPUT:
        RETVAL
    CASE: items == 3
        char *		Class;
        const char *	name;
        const char *	value;
    CODE:
        RETVAL = g_mime_param_new(name, value);
        plist = g_list_prepend(plist, RETVAL);
    OUTPUT:
        RETVAL

void
DESTROY(param)
        MIME::Fast::Param	param
    CODE:
        if (gmime_debug)
	  warn("g_mime_param_DESTROY: 0x%x", param);
        if (g_list_find(plist,param)) {
          g_mime_param_destroy (param);
          plist = g_list_remove(plist, param);
        }

 # char *
 # g_mime_param_to_string(param)
 #       MIME::Fast::Param	param

MIME::Fast::Param
g_mime_param_append(params, name, value)
	MIME::Fast::Param	params
	const char *		name
	const char *		value
    CODE:
    	RETVAL = g_mime_param_append(params, name, value);
    OUTPUT:
	RETVAL

MIME::Fast::Param
g_mime_param_append_param(params, param)
	MIME::Fast::Param	params
	MIME::Fast::Param	param
    CODE:
    	RETVAL = g_mime_param_append_param(params, param);
    OUTPUT:
	RETVAL

void
g_mime_param_write_to_string(params, fold, svtext)
	MIME::Fast::Param	params
	gboolean		fold
	SV *			&svtext
    PREINIT:
	GString			*textdata;
    CODE:
        textdata = g_string_new ("");
    	g_mime_param_write_to_string (params, fold, textdata);
	sv_catpv(svtext, textdata->str);
	g_string_free (textdata, TRUE);
    OUTPUT:
	svtext


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


MODULE = MIME::Fast		PACKAGE = MIME::Fast::MultiPart		PREFIX=g_mime_multipart_

 #
 ## CONSTRUCTION/DESCTRUCTION
 #

MIME::Fast::MultiPart
g_mime_multipart_new(Class = "MIME::Fast::MultiPart", subtype = "mixed")
        char *		Class;
        const char *		subtype;
    PROTOTYPE: $;$$
    CODE:
        RETVAL = g_mime_multipart_new_with_subtype(subtype);
        plist = g_list_prepend(plist, RETVAL);
        if (gmime_debug)
          warn("function g_mime_multipart_new (also in plist): 0x%x", RETVAL);
    OUTPUT:
        RETVAL

void
DESTROY(mime_multipart)
        MIME::Fast::MultiPart	mime_multipart
    CODE:
        if (gmime_debug)
          warn("g_mime_multipart_DESTROY: 0x%x %s", mime_multipart,
          g_list_find(plist,mime_multipart) ? "(true destroy)" : "(only attempt)");
        if (g_list_find(plist,mime_multipart)) {
          g_mime_object_unref(GMIME_OBJECT (mime_multipart));
          // g_mime_part_destroy(mime_multipart);
          plist = g_list_remove(plist, mime_multipart);
        }

const char *
g_mime_multipart_to_string (mime_multipart)
	MIME::Fast::MultiPart	mime_multipart
    CODE:
        RETVAL = g_mime_object_to_string(GMIME_OBJECT (mime_multipart));
    OUTPUT:
    	RETVAL

void
interface_p_set(mime_multipart, value)
	MIME::Fast::MultiPart	mime_multipart
	const char *	        value
    INTERFACE_MACRO:
	XSINTERFACE_FUNC
	XSINTERFACE_FUNC_MIMEFAST_MULTIPART_SET
    INTERFACE:
	set_boundary
	set_preface
	set_postface

const char *
interface_p_get(mime_multipart)
	MIME::Fast::MultiPart	mime_multipart
    INTERFACE_MACRO:
	XSINTERFACE_FUNC
	XSINTERFACE_FUNC_MIMEFAST_MULTIPART_SET
    INTERFACE:
	get_boundary
	get_preface
	get_postface

 #
 # * content_length
 #
guint
g_mime_multipart_get_content_length(mime_multipart, method = GMIME_LENGTH_CUMULATIVE)
        MIME::Fast::MultiPart	mime_multipart
        int			method
    CODE:
        RETVAL = get_content_length( GMIME_OBJECT(mime_multipart), method);
    OUTPUT:
    	RETVAL

 #
 # remove_part
 # remove_part_at
 #
void
g_mime_multipart_remove_part(mime_multipart, subpart)
        MIME::Fast::MultiPart	mime_multipart
        SV *			subpart
    PREINIT:
        GMimeObject		*mime_object = NULL;
	int			index;
    CODE:
	if (sv_isobject(subpart) && SvROK(subpart)) {
	  IV tmp = SvIV((SV*)SvRV(ST(0)));
	  mime_object = INT2PTR(MIME__Fast__Object, tmp);
          if (gmime_debug)
            warn("g_mime_part_remove_subpart: 0x%x, child=0x%x (not add to plist)", mime_multipart, mime_object);
          g_mime_multipart_remove_part(mime_multipart, mime_object);
	} else if (SvIOK(subpart)) {
	  index = SvIV(subpart);
          if (gmime_debug)
            warn("g_mime_part_remove_subpart_at: 0x%x, index=%d", mime_multipart, index);
	  g_mime_multipart_remove_part_at(mime_multipart, index);
	}
        
  # return mime part for the given numer(s)
SV *
g_mime_multipart_get_part(mime_multipart, ...)
        MIME::Fast::MultiPart	mime_multipart
    PREINIT:
        int		i, count = 0;
        IV		partnum = -1;
	GMimeMultipart  *part;
	GMimeObject     *mime_object;
        GMimeMessage	*message;
    CODE:
	if (!GMIME_IS_MULTIPART(mime_multipart))
	{
          warn("Submitted argument is not of type MIME::Fast::MultiPart");
	  XSRETURN_UNDEF;
	}

	RETVAL = &PL_sv_undef;
	part = mime_multipart;

	for (i=items - 1; part && i>0; --i) {
          
	  partnum = SvIV(ST(items - i));
	  if (partnum >= g_mime_multipart_get_number(part)) {
	    warn("MIME::Fast::MultiPart::get_part: part no. %d (index %d) is greater than no. of subparts (%d)",
			    partnum, items - i, g_mime_multipart_get_number(part));
	    if (part != mime_multipart)
	      g_mime_object_unref(GMIME_OBJECT(part));
	    XSRETURN_UNDEF;
	  }
	  mime_object = g_mime_multipart_get_part(part, partnum);

	  if (part != mime_multipart)
	    g_mime_object_unref(GMIME_OBJECT(part));

	  if (i != 1) { // more parts necessary 
	    
	    if (GMIME_IS_MESSAGE_PART(mime_object))	// message/rfc822 - returns message
	    {
	      message = g_mime_message_part_get_message ((MIME__Fast__MessagePart)mime_object);
	      g_mime_object_unref(GMIME_OBJECT(mime_object));
   
	      mime_object = GMIME_OBJECT(message->mime_part);
	      g_mime_object_ref(mime_object);
	      g_mime_object_unref(GMIME_OBJECT(message));
	    }
 
	    if (GMIME_IS_MULTIPART(mime_object))
	    {
	      part = GMIME_MULTIPART(mime_object);
	    }
	    else
	    {
	      warn("MIME::Fast::MultiPart::get_part: found part no. %d (index %d) that is not a Multipart MIME object", partnum, items - i);
	      g_mime_object_unref(mime_object);
	      XSRETURN_UNDEF;
	    }

	  }
	  else		// the last part we are looking for
	  {
	    if (GMIME_IS_OBJECT(mime_object)) {
	      RETVAL = newSViv(0);
	      if (GMIME_IS_MESSAGE_PARTIAL(mime_object))
	        sv_setref_pv(RETVAL, "MIME::Fast::MessagePartial", (MIME__Fast__MessagePartial)mime_object);
#if GMIME_CHECK_VERSION_2_0_9
	      else if (GMIME_IS_MESSAGE_MDN(mime_object))
	        sv_setref_pv(RETVAL, "MIME::Fast::MessageMDN", (MIME__Fast__MessageMDN)mime_object);
	      else if (GMIME_IS_MESSAGE_DELIVERY(mime_object))
	        sv_setref_pv(RETVAL, "MIME::Fast::MessageDelivery", (MIME__Fast__MessageDelivery)mime_object);
#endif
	      else if (GMIME_IS_MESSAGE_PART(mime_object))
	        sv_setref_pv(RETVAL, "MIME::Fast::MessagePart", (MIME__Fast__MessagePart)mime_object);
	      else if (GMIME_IS_MULTIPART(mime_object))
	        sv_setref_pv(RETVAL, "MIME::Fast::MultiPart", (MIME__Fast__MultiPart)mime_object);
	      else if (GMIME_IS_PART(mime_object))
	        sv_setref_pv(RETVAL, "MIME::Fast::Part", (MIME__Fast__Part)mime_object);
	      else
	        sv_setref_pv(RETVAL, "MIME::Fast::Object", mime_object);
              plist = g_list_prepend(plist, mime_object);
	    }
	    else
	    {
	      die("MIME::Fast::MultiPart::get_part: found unknown type of part no. %d (index %d)", partnum, items - i);
	    }
	    break;
	  }
 
	} // end of for

    OUTPUT:
        RETVAL

 #
 # subpart
 #
SV *
g_mime_multipart_get_subpart_from_content_id(mime_multipart, content_id)
        MIME::Fast::MultiPart	mime_multipart
        const char *	content_id
    PREINIT:
        GMimeObject     *mime_object = NULL;
    CODE:
        mime_object = g_mime_multipart_get_subpart_from_content_id(mime_multipart, content_id);
	RETVAL = newSViv(0);
	if (mime_object == NULL)
	  XSRETURN_UNDEF;
	else if (GMIME_IS_MULTIPART(mime_object))
	  sv_setref_pv(RETVAL, "MIME::Fast::MultiPart", (GMimeMultipart *)mime_object);
	else if (GMIME_IS_MESSAGE(mime_object))
	  sv_setref_pv(RETVAL, "MIME::Fast::Message", (GMimeMessage *)mime_object);
	else if (GMIME_IS_MESSAGE_PARTIAL(mime_object))
	  sv_setref_pv(RETVAL, "MIME::Fast::MessagePartial", (GMimeMessagePartial *)mime_object);
#if GMIME_CHECK_VERSION_2_0_9
	else if (GMIME_IS_MESSAGE_MDN(mime_object))
	  sv_setref_pv(RETVAL, "MIME::Fast::MessageMDN", (GMimeMessageMDN *)mime_object);
	else if (GMIME_IS_MESSAGE_DELIVERY(mime_object))
	  sv_setref_pv(RETVAL, "MIME::Fast::MessageDelivery", (GMimeMessageDelivery *)mime_object);
#endif
	else if (GMIME_IS_MESSAGE_PART(mime_object))
	  sv_setref_pv(RETVAL, "MIME::Fast::MessagePart", (GMimeMessagePart *)mime_object);
	else if (GMIME_IS_PART(mime_object))
	  sv_setref_pv(RETVAL, "MIME::Fast::Part", (void*)mime_object);
	else
	  die("g_mime_multipart_get_subpart_from_content_id: unknown type of object: 0x%x", mime_object);
	g_mime_object_ref( mime_object );
        plist = g_list_prepend(plist, RETVAL);
        if (gmime_debug)
          warn("function g_mime_multipart_get_subpart_from_content_id (also in plist): 0x%x", RETVAL);
    OUTPUT:
        RETVAL

 #
 # add_part
 # add_part_at
 #
void
g_mime_multipart_add_part(mime_multipart, subpart, index = 0)
    CASE: items == 2
        MIME::Fast::MultiPart	mime_multipart
        SV *			subpart
    PREINIT:
	GMimeObject		*mime_object;
    CODE:
	if (sv_isobject(subpart) && SvROK(subpart)) {
	  IV tmp = SvIV((SV*)SvRV(ST(0)));
	  mime_object = INT2PTR(MIME__Fast__Object, tmp);
          g_mime_multipart_add_part(mime_multipart, mime_object);
          plist = g_list_remove(plist, subpart);
	}
    CASE: items == 3
        MIME::Fast::MultiPart	mime_multipart
        SV *			subpart
	int			index
    PREINIT:
	GMimeObject		*mime_object;
    CODE:
	if (sv_isobject(subpart) && SvROK(subpart)) {
	  IV tmp = SvIV((SV*)SvRV(ST(0)));
	  mime_object = INT2PTR(MIME__Fast__Object, tmp);
          g_mime_multipart_add_part_at(mime_multipart, mime_object, index);
          plist = g_list_remove(plist, subpart);
	}

 #
 # get_number (number of parts)
 #
int
g_mime_multipart_get_number(mime_multipart)
        MIME::Fast::MultiPart		mime_multipart

 #
 # callback function
 #
void
g_mime_multipart_foreach(mime_multipart, callback, svdata)
        MIME::Fast::MultiPart		mime_multipart
        SV *			callback
        SV *			svdata
    PREINIT:
	struct _user_data_sv    *data;
    CODE:
	data = g_new0 (struct _user_data_sv, 1);
	data->svuser_data = svdata;
	data->svfunc = callback;
        g_mime_multipart_foreach(mime_multipart, call_sub_foreach, data);
	g_free (data);

 #
 # children
 # ALIAS: parts
 #
void
children(mime_multipart, ...)
        MIME::Fast::MultiPart	mime_multipart
    ALIAS:
        MIME::Fast::MultiPart::parts = 1
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
        if (GMIME_IS_MULTIPART (mime_multipart)) {
          for (child = GMIME_MULTIPART (mime_multipart)->subparts; child && child->data; child = child->next, ++count) {
            SV * part;
	    if (gmime_debug)
	    warn(" ** children 0x%x\n", child->data);
            if (items == 1 && gimme == G_SCALAR)
              continue;

            # avoid unnecessary SV creation
            if (items == 2 && partnum != count)
              continue;

            # push part
            part = sv_newmortal();
            if (GMIME_IS_MULTIPART(child->data))
	    {
	      if (gmime_debug)
	      warn(" ** children add: %s 0x%x\n", "MIME::Fast::MultiPart", child->data);
	      sv_setref_pv(part, "MIME::Fast::MultiPart", (MIME__Fast__MultiPart)(child->data));
	    } else if (GMIME_IS_MESSAGE_PARTIAL(child->data))
	    {
	      if (gmime_debug)
	      warn(" ** children add: %s 0x%x\n", "MIME::Fast::MessagePartial", child->data);
              sv_setref_pv(part, "MIME::Fast::MessagePartial", (MIME__Fast__MessagePartial)(child->data));
#if GMIME_CHECK_VERSION_2_0_9
	    } else if (GMIME_IS_MESSAGE_MDN(child->data))
	    {
	      if (gmime_debug)
	      warn(" ** children add: %s 0x%x\n", "MIME::Fast::MessageMDN", child->data);
              sv_setref_pv(part, "MIME::Fast::MessageMDN", (MIME__Fast__MessageMDN)(child->data));
	    } else if (GMIME_IS_MESSAGE_DELIVERY(child->data))
	    {
	      if (gmime_debug)
	      warn(" ** children add: %s 0x%x\n", "MIME::Fast::MessageDelivery", child->data);
              sv_setref_pv(part, "MIME::Fast::MessageDelivery", (MIME__Fast__MessageDelivery)(child->data));
#endif
	    } else if (GMIME_IS_PART(child->data))
	    {
	      if (gmime_debug)
	      warn(" ** children add: %s 0x%x\n", "MIME::Fast::Part", child->data);
              sv_setref_pv(part, "MIME::Fast::Part", (MIME__Fast__Part)(child->data));
	    } else if (GMIME_IS_MESSAGE_PART(child->data))
	    {
	      if (gmime_debug)
	      warn(" ** children add: %s 0x%x\n", "MIME::Fast::MessagePart", child->data);
              sv_setref_pv(part, "MIME::Fast::MessagePart", (MIME__Fast__MessagePart)(child->data));
	    } else if (GMIME_IS_OBJECT(child->data))
	      die("g_mime_multipart children: unknown type of object: 0x%x '%s'",
	        child->data, g_mime_content_type_to_string(g_mime_object_get_content_type(child->data)));
	    else
	      die("g_mime_multipart children: unknown reference (not GMIME object): 0x%x '%5s'",
			       child->data, child->data);

            if (gmime_debug)
              warn("function g_mime_part subparts setref (not in plist): 0x%x", child->data);

            if (items == 1) {
              XPUSHs(part);
            } else if (partnum == count) {
              XPUSHs(part);
              break;
            }
          }
          if (gimme == G_SCALAR && partnum == -1)
            XPUSHs(sv_2mortal(newSViv(count)));
        }


MODULE = MIME::Fast		PACKAGE = MIME::Fast::Part		PREFIX=g_mime_part_

 #
 ## CONSTRUCTION/DESCTRUCTION
 #

MIME::Fast::Part
g_mime_part_new(Class = "MIME::Fast::Part", type = "text", subtype = "plain")
        char *		Class;
        const char *		type;
        const char *		subtype;
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
          g_mime_object_unref(GMIME_OBJECT (mime_part));
          plist = g_list_remove(plist, mime_part);
        }

 #
 ## ACCESSOR FUNCTIONS
 #

 ## INTERFACE: keyword does not work with perl v5.6.0
 ## (unknown cv variable during C compilation)
 ## oh... it is working now in 5.8.0

void
interface_p_set(mime_part, value)
	MIME::Fast::Part	mime_part
	char *			    value
    INTERFACE_MACRO:
	XSINTERFACE_FUNC
	XSINTERFACE_FUNC_MIMEFAST_PART_SET
    INTERFACE:
	set_content_description
	set_content_id
	set_content_md5
	set_content_location
	set_content_disposition
	set_filename


const char *
interface_p_get(mime_part)
	MIME::Fast::Part	mime_part
    INTERFACE_MACRO:
	XSINTERFACE_FUNC
	XSINTERFACE_FUNC_MIMEFAST_PART_SET
    INTERFACE:
	get_content_description
	get_content_id
	get_content_md5
	get_content_location
	get_content_disposition
	get_filename

 #
 # content_header
 #
void
g_mime_part_set_content_header(mime_part, field, value)
	MIME::Fast::Part	mime_part
        const char *		field
        const char *		value

const char *
g_mime_part_get_content_header(mime_part, field)
	MIME::Fast::Part	mime_part
        const char *		field

 #
 # content_md5
 #

gboolean
g_mime_part_verify_content_md5(mime_part)
        MIME::Fast::Part	mime_part
        
 #
 # * content_length
 #
guint
g_mime_part_get_content_length(mime_part, method = GMIME_LENGTH_CUMULATIVE)
        MIME::Fast::Part	mime_part
        int			method
    CODE:
        RETVAL = get_content_length( GMIME_OBJECT(mime_part), method);
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

# looking for g_mime_part_get_content_type(mime_part)? it is in MIME::Fast::Object

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
const char *
g_mime_part_encoding_to_string(encoding)
        MIME::Fast::PartEncodingType		encoding
    CODE:
        RETVAL = g_mime_part_encoding_to_string(encoding);
    OUTPUT:
    	RETVAL

MIME::Fast::PartEncodingType
g_mime_part_encoding_from_string(encoding)
        const char *		encoding
    CODE:
        RETVAL = g_mime_part_encoding_from_string(encoding);
    OUTPUT:
    	RETVAL

 #
 # content_disposition_parameter
 #
void
g_mime_part_add_content_disposition_parameter(mime_part, name, value)
        MIME::Fast::Part	mime_part
        const char *		name
        const char *		value
    CODE:
        g_mime_part_add_content_disposition_parameter(mime_part, name, value);

const char *
g_mime_part_get_content_disposition_parameter(mime_part, name)
        MIME::Fast::Part	mime_part
        const char *		name
    CODE:
        RETVAL = g_mime_part_get_content_disposition_parameter(mime_part, name);
    OUTPUT:
    	RETVAL

void
g_mime_part_set_content_disposition_object(mime_part, mime_disposition)
        MIME::Fast::Part		mime_part
	MIME::Fast::Disposition		mime_disposition

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
	  PerlIO *pio;
	  FILE *fp;
	  int fd;

	  pio = IoIFP(sv_2io(svval));
	  if (!pio || !(fp = PerlIO_findFILE(pio))) {
	    croak("MIME::Fast::Part::set_content: the argument you gave is not a FILE pointer");
	  }
	    
	  fd = dup(fileno(fp));
	  if (fd == -1)
	    croak("MIME::Fast::Part::set_content: Can not duplicate a FILE pointer");

          // mime_stream = g_mime_stream_file_new(fp);
          mime_stream = g_mime_stream_fs_new(fd);
	  if (!mime_stream) {
	    close(fd);
	    XSRETURN_UNDEF;
          }
	  // g_mime_stream_file_set_owner (mime_stream, FALSE);
          mime_data_wrapper = g_mime_data_wrapper_new_with_stream(mime_stream, GMIME_PART_ENCODING_BASE64);
          g_mime_part_set_content_object(mime_part, mime_data_wrapper);

          g_mime_stream_unref(mime_stream);
	} else if (svvaltype == SVt_PVMG) { // possible STDIN/STDOUT etc.
          int fd0 = (int)SvIV( svval );
	  int fd;

	  if (fd0 < 0 || (fd = dup(fd0)) == -1)
	    croak("MIME::Fast::Part::set_content: Can not duplicate a FILE pointer");

          mime_stream = g_mime_stream_fs_new(fd);
	  if (!mime_stream) {
	    close(fd);
	    XSRETURN_UNDEF;
          }
          mime_data_wrapper = g_mime_data_wrapper_new_with_stream(mime_stream, GMIME_PART_ENCODING_BASE64);
          g_mime_part_set_content_object(mime_part, mime_data_wrapper);

          g_mime_stream_unref(mime_stream);
        } else if (SvPOK(svval)) {
          data = (char *)SvPV(svval, len);
          g_mime_part_set_content(mime_part, data, len);
        } else {
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
        const char * content_char;
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
 ## UTILITY FUNCTIONS
 #

void
g_mime_part_foreach(mime_part, callback, svdata)
        MIME::Fast::Part	mime_part
        SV *			callback
        SV *			svdata
    PREINIT:
	struct _user_data_sv    *data;
    CODE:
	data = g_new0 (struct _user_data_sv, 1);
	data->svuser_data = svdata;
	data->svfunc = callback;
	call_sub_foreach( GMIME_OBJECT(mime_part), data);
	g_free (data);


MODULE = MIME::Fast		PACKAGE = MIME::Fast::Message	PREFIX=g_mime_message_

# new(pretty_headers)
MIME::Fast::Message
g_mime_message_new(Class, pretty_headers = FALSE)
        char *		Class
        gboolean	pretty_headers
    CODE:
        RETVAL = g_mime_message_new(pretty_headers);
	if (gmime_debug)
          warn("g_mime_message_NEW: 0x%x\n", RETVAL);
        plist = g_list_prepend(plist, RETVAL);
    OUTPUT:
        RETVAL

# destroy(message)
void
DESTROY(message)
        MIME::Fast::Message	message
    CODE:
        if (gmime_debug)
          warn("g_mime_message_DESTROY: 0x%x %s", message,
            g_list_find(plist,message) ? "(true destroy)" : "(only attempt)");
        if (g_list_find(plist,message)) {
          g_mime_object_unref (GMIME_OBJECT (message));
          plist = g_list_remove(plist, message);
	}

# sender
void
g_mime_message_test_type(message)
        MIME::Fast::Message	message
    CODE:
	warn(" ** Testing message 0x%x\n", message);
	warn(" ** Message is message: %s\n", GMIME_IS_MESSAGE(message) ? "true" : "false");


# recipient
void
g_mime_message_add_recipient(message, type, name, address)
        MIME::Fast::Message	message
        char *		type
        const char *	name
        const char *	address

void
g_mime_message_add_recipients_from_string(message, type, recipients)
 	MIME::Fast::Message	message
        char *		type
        const char *	recipients

AV *
g_mime_message_get_recipients(message, type)
        MIME::Fast::Message	message
        const char *	type
    PREINIT:
        InternetAddressList *		rcpt;
        AV * 		retav;
    CODE:
        retav = newAV();
        rcpt = g_mime_message_get_recipients(message, type);
        while (rcpt) {
          SV * address = newSViv(0);
          sv_setref_pv(address, "MIME::Fast::InternetAddress", (MIME__Fast__InternetAddress)(rcpt->address));
          av_push(retav, address);
          rcpt = rcpt->next;
        }
        RETVAL = retav;
    OUTPUT:
        RETVAL


void
interface_m_set(message, value)
        MIME::Fast::Message	message
	char *			value
    INTERFACE_MACRO:
	XSINTERFACE_FUNC
	XSINTERFACE_FUNC_MIMEFAST_MESSAGE_SET
    INTERFACE:
	set_subject
	set_message_id
	set_reply_to
	set_sender

const char *
interface_m_get(message)
        MIME::Fast::Message	message
    INTERFACE_MACRO:
	XSINTERFACE_FUNC
	XSINTERFACE_FUNC_MIMEFAST_MESSAGE_SET
    INTERFACE:
	get_subject
	get_message_id
	get_reply_to
	get_sender
        
 # date
void
g_mime_message_set_date(message, date, gmt_offset)
        MIME::Fast::Message	message
        time_t		date
        int		gmt_offset

void
g_mime_message_set_date_from_string(message, str)
        MIME::Fast::Message	message
        const char *	str

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
	char *		str;
    PPCODE:
        if (gimme == G_SCALAR) {
          str = g_mime_message_get_date_string(message);
	  if (str) {
            XPUSHs(sv_2mortal(newSVpv(str,0)));
	    g_free (str);
	  }
        } else if (gimme == G_ARRAY) {
          g_mime_message_get_date(message, &date, &gmt_offset);
          XPUSHs(sv_2mortal(newSVnv(date)));
          XPUSHs(sv_2mortal(newSViv(gmt_offset)));
        }

# the other headers
void
g_mime_message_set_header(message, field, value)
        MIME::Fast::Message	message
        const char *	field
        const char *	value
    CODE:
        g_mime_message_set_header(message, field, value);
        // message_set_header(message, field, value);
    	

void
g_mime_message_remove_header(message, field)
        MIME::Fast::Message	message
        const char *	field
    CODE:
        g_mime_object_remove_header(GMIME_OBJECT (message), field);

 # add arbitrary header
void
g_mime_message_add_header(message, field, value)
        MIME::Fast::Message	message
        const char *	field
        const char *	value

# CODE:
#	message_set_header(message, field, value);

const char *
g_mime_message_get_header(message, field)
        MIME::Fast::Message	message
        const char *	field

# mime_part
void
g_mime_message_set_mime_part(message, mime_part)
        MIME::Fast::Message	message
        MIME::Fast::Part	mime_part
    CODE:
        g_mime_message_set_mime_part(message, GMIME_OBJECT (mime_part));
        plist = g_list_remove(plist, mime_part);

## UTILITY FUNCTIONS

SV *
g_mime_message_get_body(message, want_plain = 1, is_html = 0)
    CASE: items == 1
        MIME::Fast::Message	message
    PREINIT:
        gboolean	want_plain = 1;
        gboolean	is_html;
	char *		textdata;
    CODE:
        textdata = g_mime_message_get_body(message, want_plain, &is_html);
	if (textdata == NULL)
	  XSRETURN_UNDEF;
        RETVAL = newSVpv(textdata, 0);
	g_free (textdata);
    OUTPUT:
        RETVAL
    CASE: items == 2
        MIME::Fast::Message	message
        gboolean	want_plain
    PREINIT:
        gboolean	is_html;
	char *		textdata;
    CODE:
        textdata = g_mime_message_get_body(message, want_plain, &is_html);
	if (textdata == NULL)
	  XSRETURN_UNDEF;
        RETVAL = newSVpv(textdata, 0);
	g_free (textdata);
    OUTPUT:
        RETVAL
    CASE: items == 3
        MIME::Fast::Message	message
        gboolean	want_plain
        gboolean	&is_html
    PREINIT:
	char *		textdata;
    CODE:
        textdata = g_mime_message_get_body(message, want_plain, &is_html);
	if (textdata == NULL)
	  XSRETURN_UNDEF;
        RETVAL = newSVpv(textdata, 0);
	g_free (textdata);
    OUTPUT:
        is_html
        RETVAL
        

SV *
g_mime_message_get_headers(message)
        MIME::Fast::Message	message
    PREINIT:
	char *		textdata;
    CODE:
	textdata = g_mime_message_get_headers(message);
	if (textdata == NULL)
	  XSRETURN_UNDEF;
        RETVAL = newSVpv(textdata, 0);
	g_free (textdata);
    OUTPUT:
        RETVAL

# callback function
void
g_mime_message_foreach_part(message, callback, svdata)
        MIME::Fast::Message	message
        SV *			callback
        SV *			svdata
    PREINIT:
	struct _user_data_sv    *data;

    CODE:
	data = g_new0 (struct _user_data_sv, 1);
	data->svuser_data = svdata;
	data->svfunc = callback;
        g_mime_message_foreach_part(message, call_sub_foreach, data);
	g_free (data);

## "OBJECTS" FUNCTION

 # returns Part or MultiPart
SV *
get_mime_part(message)
        MIME::Fast::Message	message
    PREINIT:
    	GMimeObject *	mime_object;
    CODE:
        if (message->mime_part != NULL) {
	  RETVAL = newSViv(4);
          mime_object = GMIME_OBJECT(message->mime_part);
          if (GMIME_IS_MULTIPART(mime_object))
	    sv_setref_pv(RETVAL, "MIME::Fast::MultiPart", (MIME__Fast__MultiPart)mime_object);
	  else if (GMIME_IS_MESSAGE_PARTIAL(mime_object))
	    sv_setref_pv(RETVAL, "MIME::Fast::MessagePartial", (MIME__Fast__MessagePartial)mime_object);
#if GMIME_CHECK_VERSION_2_0_9
	  else if (GMIME_IS_MESSAGE_MDN(mime_object))
	    sv_setref_pv(RETVAL, "MIME::Fast::MessageMDN", (MIME__Fast__MessageMDN)mime_object);
	  else if (GMIME_IS_MESSAGE_DELIVERY(mime_object))
	    sv_setref_pv(RETVAL, "MIME::Fast::MessageDelivery", (MIME__Fast__MessageDelivery)mime_object);
#endif
	  else if (GMIME_IS_PART(mime_object))
	    sv_setref_pv(RETVAL, "MIME::Fast::Part", (MIME__Fast__Part)mime_object);
	  else if (GMIME_IS_MESSAGE_PART(mime_object))
	    sv_setref_pv(RETVAL, "MIME::Fast::MessagePart", (MIME__Fast__MessagePart)mime_object);
	  else
	    die("get_mime_part: unknown type of object: 0x%x", mime_object);
          plist = g_list_prepend(plist, RETVAL);
	  g_mime_object_ref( mime_object );
          if (gmime_debug)
            warn("function message->mime_part returns (not in plist): 0x%x", RETVAL);
	} else {
	  RETVAL = &PL_sv_undef;
	}
    OUTPUT:
        RETVAL


MODULE = MIME::Fast		PACKAGE = MIME::Fast::MessagePart	PREFIX=g_mime_message_part_

 # new(subtype)
 # new(subtype, message)
MIME::Fast::MessagePart
g_mime_message_part_new(Class, subtype = "rfc822", message = NULL)
    CASE: items <= 1
    CODE:
    	RETVAL = g_mime_message_part_new(NULL);
        plist = g_list_prepend(plist, RETVAL);
    CASE: items == 2
        char *			Class
        char *			subtype
    CODE:
    	RETVAL = g_mime_message_part_new(subtype);
        plist = g_list_prepend(plist, RETVAL);
    CASE: items == 3
        char *			Class
        char *			subtype
	MIME::Fast::Message	message
    CODE:
        RETVAL = g_mime_message_part_new_with_message(subtype, message);
        plist = g_list_prepend(plist, RETVAL);
    OUTPUT:
        RETVAL

# destroy(messagepart)
void
DESTROY(messagepart)
        MIME::Fast::MessagePart	messagepart
    CODE:
        if (gmime_debug)
          warn("g_mime_message_part_DESTROY: 0x%x %s", messagepart,
          g_list_find(plist,messagepart) ? "(true destroy)" : "(only attempt)");
        if (g_list_find(plist,messagepart)) {
          g_mime_object_unref (GMIME_OBJECT (messagepart));
          plist = g_list_remove(plist, messagepart);
	}

# sender
void
g_mime_message_part_set_message(messagepart, message)
        MIME::Fast::MessagePart	messagepart
        MIME::Fast::Message	message

MIME::Fast::Message
g_mime_message_part_get_message(messagepart)
        MIME::Fast::MessagePart	messagepart
    CODE:
	RETVAL = g_mime_message_part_get_message(messagepart);
	if (gmime_debug)
          warn("g_mime_message_part_get_message: 0x%x\n", RETVAL);
        plist = g_list_prepend(plist, RETVAL);
	g_mime_object_ref(GMIME_OBJECT(RETVAL));
    OUTPUT:
	RETVAL


MODULE = MIME::Fast		PACKAGE = MIME::Fast::MessagePartial	PREFIX=g_mime_message_partial_

 # new(id, number, total)
MIME::Fast::MessagePartial
g_mime_message_part_new(Class, id, number, total)
        char *			Class
        char *			id
	int			number
	int			total
    CODE:
    	RETVAL = g_mime_message_partial_new(id, number, total);
        plist = g_list_prepend(plist, RETVAL);
    OUTPUT:
        RETVAL

# destroy(partial)
void
DESTROY(partial)
        MIME::Fast::MessagePartial	partial
    CODE:
        if (gmime_debug)
          warn("g_mime_message_partial_DESTROY: 0x%x %s", partial,
          g_list_find(plist,partial) ? "(true destroy)" : "(only attempt)");
        if (g_list_find(plist,partial)) {
          g_mime_object_unref (GMIME_OBJECT (partial));
          plist = g_list_remove(plist, partial);
	}

const char *
g_mime_message_partial_get_id(partial)
	MIME::Fast::MessagePartial	partial

int
g_mime_message_partial_get_number(partial)
	MIME::Fast::MessagePartial	partial

int
g_mime_message_partial_get_total(partial)
	MIME::Fast::MessagePartial	partial

MIME::Fast::Message
g_mime_message_partial_reconstruct_message(svmixed)
	SV *			svmixed
    PREINIT:
	SV *			svvalue;
	AV *			avvalue;
	svtype			svvaltype;
	size_t			nparts = 0, i;
	GMimeMessagePartial	**msg_list, *partial;
	GMimeMessage		*message;
	GPtrArray		*parts;
	I32			avlen;
    CODE:
	svvalue = svmixed;
	if (SvROK(svmixed)) {
	  svvalue = SvRV(svmixed);
	}
	svvaltype = SvTYPE(svvalue);
	
	parts = g_ptr_array_new ();
	if (svvaltype == SVt_PVAV) {
	  AV *	avvalue;
	  I32		i, avlen;
	  SV *	svtmp;
	  IV tmp;

	  /* set header */
	  avvalue = (AV *)svvalue;
	  avlen = av_len(avvalue); // highest index in the array
          if (avlen == -1) {
        	croak("Usage: MIME::Fast::MessagePartial::reconstruct_message([partial,[partial]+])");
		XSRETURN_UNDEF;
	  }
	  for (i=0; i<=avlen; ++i) {
	    svtmp = (SV *)(*(av_fetch(avvalue, i, 0)));
	    tmp = SvIV((SV*)SvRV(svtmp));
	    if (tmp) {
	      if (GMIME_IS_MESSAGE (tmp) && GMIME_IS_MESSAGE_PARTIAL (GMIME_MESSAGE(tmp)->mime_part)) {
	        partial = INT2PTR(MIME__Fast__MessagePartial, GMIME_MESSAGE(tmp)->mime_part);
	      } else if (GMIME_IS_MESSAGE_PARTIAL(tmp)) {
	        partial = INT2PTR(MIME__Fast__MessagePartial, tmp);
	      } else {
		warn("MIME::Fast::Message::reconstruct_message: Unknown type of object 0x%x", tmp);
		continue;
	      }
	      g_ptr_array_add (parts, partial);
	    }
	  }
	}

	msg_list = (GMimeMessagePartial **) parts->pdata;
	message = g_mime_message_partial_reconstruct_message(msg_list, parts->len);
	RETVAL = message;
	if (gmime_debug)
          warn("MIME::Fast::Message::reconstruct_message: 0x%x\n", RETVAL);
	plist = g_list_prepend(plist, message);
	g_ptr_array_free (parts, FALSE);
    OUTPUT:
	RETVAL

AV *
g_mime_message_partial_split_message(message, max_size)
	MIME::Fast::Message	message
	size_t			max_size
    PREINIT:
	size_t			nparts = 0;
	int			i = 0;
        AV * 			retav;
	GMimeMessage		**msg_list = NULL;
	GMimeMessage		*msg_item = NULL;
	SV *			svmsg;
    CODE:
	retav = newAV();
	msg_list = g_mime_message_partial_split_message(message, max_size, &nparts);
	if (nparts < 1)
	  XSRETURN_UNDEF;
	// for nparts == 1 msg_list[0] is equal to message, then double destruction is necessary
	for (i = 0; i < nparts; ++i) {
		svmsg = newSViv(0);
		sv_setref_pv(svmsg, "MIME::Fast::Message", (void *)msg_list[i]);
		av_push(retav, svmsg);
        	plist = g_list_prepend(plist, msg_list[i]);
	}
	g_free(msg_list);
	RETVAL = retav;
    OUTPUT:
	RETVAL

#if GMIME_CHECK_VERSION_2_0_9

MODULE = MIME::Fast		PACKAGE = MIME::Fast::MessageDelivery	PREFIX=g_mime_message_delivery_

MIME::Fast::MessageDelivery
g_mime_message_part_new(Class)
        char *			Class
    CODE:
    	RETVAL = g_mime_message_delivery_new();
        plist = g_list_prepend(plist, RETVAL);
    OUTPUT:
        RETVAL

# destroy(delivery)
void
DESTROY(delivery)
        MIME::Fast::MessageDelivery	delivery
    CODE:
        if (gmime_debug)
          warn("g_mime_message_delivery_DESTROY: 0x%x %s", delivery,
          g_list_find(plist,delivery) ? "(true destroy)" : "(only attempt)");
        if (g_list_find(plist,delivery)) {
          g_mime_object_unref (GMIME_OBJECT (delivery));
          plist = g_list_remove(plist, delivery);
	}

void
g_mime_message_delivery_set_per_message(delivery, svmixed)
        MIME::Fast::MessageDelivery	delivery
	SV *				svmixed
    PREINIT:
	SV *			svvalue;
	svtype			svvaltype;
	GMimeHeader		*header;
    CODE:
	svvalue = svmixed;
	if (SvROK(svmixed)) {
	  svvalue = SvRV(svmixed);
	}
	svvaltype = SvTYPE(svvalue);
	if (svvaltype == SVt_PVHV) {
	  HV *		hvarray;
	  I32		keylen;
	  SV *	svtmp, *svval;
	  IV tmp;
	  char *key;

	  hvarray = (HV *)svvalue;
	  header = g_mime_header_new();
	  while ((svval = hv_iternextsv(hvarray, &key, &keylen)) != NULL)
	  {
		  g_mime_header_add(header, key, (const char *)SvPV_nolen(svval));
	  }
	  g_mime_message_delivery_set_per_message(delivery, header);
	} else {
        	croak("Usage: MIME::Fast::MessageDelivery::add_per_rcpt(\%array_of_headers)");
		XSRETURN_UNDEF;
	}




SV *
g_mime_message_delivery_get_per_message(delivery)
        MIME::Fast::MessageDelivery	delivery
    PREINIT:
	GMimeHeader *		header;
	struct raw_header *	h;
	HV *			rh;
    CODE:
	header = g_mime_message_delivery_get_per_message(delivery);
	if (!header) {
		XSRETURN_UNDEF;
	}
	rh = (HV *)sv_2mortal((SV *)newHV());
	h = header->headers;
	while (h && h->name) {
		hv_store(rh, h->name, 0, newSVpv(h->value, 0), 0);
		h = h->next;
	}
	g_mime_header_destroy(header);
	RETVAL = newRV((SV *)rh);
    OUTPUT:
	RETVAL


void
g_mime_message_delivery_remove_per_message(delivery)
        MIME::Fast::MessageDelivery	delivery


void
g_mime_message_delivery_add_per_recipient(delivery, svmixed = 0)
    CASE: items == 1
        MIME::Fast::MessageDelivery	delivery
    CODE:
	g_mime_message_delivery_add_per_recipient(delivery, NULL);
    CASE: items == 2
        MIME::Fast::MessageDelivery	delivery
	SV *				svmixed
    PREINIT:
	SV *			svvalue;
	svtype			svvaltype;
	GMimeHeader		*header;
    CODE:
	svvalue = svmixed;
	if (SvROK(svmixed)) {
	  svvalue = SvRV(svmixed);
	}
	svvaltype = SvTYPE(svvalue);
	if (svvaltype == SVt_PVHV) {
	  HV *		hvarray;
	  I32		keylen;
	  SV *	svtmp, *svval;
	  IV tmp;
	  char *key;

	  hvarray = (HV *)svvalue;
	  header = g_mime_header_new();
	  while ((svval = hv_iternextsv(hvarray, &key, &keylen)) != NULL)
	  {
		  g_mime_header_add(header, key, (const char *)SvPV_nolen(svval));
	  }
	  g_mime_message_delivery_add_per_recipient(delivery, header);
	} else {
        	croak("Usage: MIME::Fast::MessageDelivery::add_per_rcpt(\%array_of_headers)");
		XSRETURN_UNDEF;
	}

SV *
g_mime_message_delivery_get_per_recipient(delivery, rcpt_index)
        MIME::Fast::MessageDelivery	delivery
	int				rcpt_index
    PREINIT:
	GMimeHeader *		header;
	struct raw_header *	h;
	HV *			rh;
    CODE:
	header = g_mime_message_delivery_get_per_recipient(delivery, rcpt_index);
	if (!header) {
		XSRETURN_UNDEF;
	}
	rh = (HV *)sv_2mortal((SV *)newHV());
	h = header->headers;
	while (h && h->name) {
		hv_store(rh, h->name, 0, newSVpv(h->value, 0), 0);
		h = h->next;
	}
	g_mime_header_destroy(header);
	RETVAL = newRV((SV *)rh);
    OUTPUT:
	RETVAL


void
g_mime_message_delivery_remove_per_recipient(delivery, rcpt_index)
        MIME::Fast::MessageDelivery	delivery
	int				rcpt_index


const char *
g_mime_message_delivery_get_original_envelope_id(delivery)
        MIME::Fast::MessageDelivery	delivery


void
g_mime_message_delivery_set_original_envelope_id(delivery, value)
        MIME::Fast::MessageDelivery	delivery
	const char *			value

const char *
g_mime_message_delivery_get_reporting_mta(delivery)
        MIME::Fast::MessageDelivery	delivery

void
g_mime_message_delivery_set_reporting_mta(delivery, value)
        MIME::Fast::MessageDelivery	delivery
	const char *			value

const char *
g_mime_message_delivery_get_dsn_gateway(delivery)
        MIME::Fast::MessageDelivery	delivery

void
g_mime_message_delivery_set_dsn_gateway(delivery, value)
        MIME::Fast::MessageDelivery	delivery
	const char *			value

const char *
g_mime_message_delivery_get_received_from_mta(delivery)
        MIME::Fast::MessageDelivery	delivery

void
g_mime_message_delivery_set_received_from_mta(delivery, value)
        MIME::Fast::MessageDelivery	delivery
	const char *			value

void
g_mime_message_delivery_set_arrival_date_string(delivery, value)
        MIME::Fast::MessageDelivery	delivery
	const char *			value

 #
 # returns scalar string or array (date, gmt_offset)
 #
void
g_mime_message_delivery_get_arrival_date(delivery)
        MIME::Fast::MessageDelivery	delivery
    PREINIT:
        time_t		date;
        int		gmt_offset;
        I32		gimme = GIMME_V;
	char *		str;
    PPCODE:
        if (gimme == G_SCALAR) {
          str = g_mime_message_delivery_get_arrival_date_string(delivery);
	  if (str) {
            XPUSHs(sv_2mortal(newSVpv(str,0)));
	    g_free (str);
	  }
        } else if (gimme == G_ARRAY) {
          g_mime_message_delivery_get_arrival_date(delivery, &date, &gmt_offset);
          XPUSHs(sv_2mortal(newSVnv(date)));
          XPUSHs(sv_2mortal(newSViv(gmt_offset)));
        }

void
g_mime_message_delivery_set_arrival_date(delivery, date, gmt_offset)
        MIME::Fast::MessageDelivery	delivery
        time_t		date
        int		gmt_offset

const char *
g_mime_message_delivery_get_msg_header(delivery, name)
        MIME::Fast::MessageDelivery	delivery
	const char *			name

void
g_mime_message_delivery_set_msg_header(delivery, name, value)
        MIME::Fast::MessageDelivery	delivery
	const char *			name
	const char *			value

void
g_mime_message_delivery_remove_msg_header(delivery, name)
        MIME::Fast::MessageDelivery	delivery
	const char *			name

int
g_mime_message_delivery_get_rcpt_length(delivery)
        MIME::Fast::MessageDelivery	delivery

const char *
g_mime_message_delivery_get_rcpt_original_recipient(delivery, rcpt_index)
        MIME::Fast::MessageDelivery	delivery
	int				rcpt_index

void
g_mime_message_delivery_set_rcpt_original_recipient(delivery, rcpt_index, value)
        MIME::Fast::MessageDelivery	delivery
	int				rcpt_index
	const char *			value

const char *
g_mime_message_delivery_get_rcpt_final_recipient(delivery, rcpt_index)
        MIME::Fast::MessageDelivery	delivery
	int				rcpt_index

void
g_mime_message_delivery_set_rcpt_final_recipient(delivery, rcpt_index, value)
        MIME::Fast::MessageDelivery	delivery
	int				rcpt_index
	const char *			value

const char *
g_mime_message_delivery_get_rcpt_action(delivery, rcpt_index)
        MIME::Fast::MessageDelivery	delivery
	int				rcpt_index

void
g_mime_message_delivery_set_rcpt_action(delivery, rcpt_index, value)
        MIME::Fast::MessageDelivery	delivery
	int				rcpt_index
	const char *			value

SV *
g_mime_message_delivery_get_rcpt_status(delivery, rcpt_index)
        MIME::Fast::MessageDelivery	delivery
	int				rcpt_index
    PREINIT:
	char *	textdata;
    CODE:
	textdata = g_mime_message_delivery_get_rcpt_status(delivery, rcpt_index);
	if (textdata) {
	  RETVAL = newSVpv(textdata, 0);
	  g_free (textdata);
	} else {
	  XSRETURN_UNDEF;
	}
    OUTPUT:
	RETVAL


void
g_mime_message_delivery_set_rcpt_status(delivery, rcpt_index, value)
        MIME::Fast::MessageDelivery	delivery
	int				rcpt_index
	const char *			value

const char *
g_mime_message_delivery_get_rcpt_remote_mta(delivery, rcpt_index)
        MIME::Fast::MessageDelivery	delivery
	int				rcpt_index

void
g_mime_message_delivery_set_rcpt_remote_mta(delivery, rcpt_index, value)
        MIME::Fast::MessageDelivery	delivery
	int				rcpt_index
	const char *			value

const char *
g_mime_message_delivery_get_rcpt_diagnostic_code(delivery, rcpt_index)
        MIME::Fast::MessageDelivery	delivery
	int				rcpt_index


void
g_mime_message_delivery_set_rcpt_diagnostic_code(delivery, rcpt_index, value)
        MIME::Fast::MessageDelivery	delivery
	int				rcpt_index
	const char *			value


 #
 # returns scalar string or array (date, gmt_offset)
 #
void
g_mime_message_delivery_get_rcpt_last_attempt_date(delivery, rcpt_index)
        MIME::Fast::MessageDelivery	delivery
	int				rcpt_index
    PREINIT:
        time_t		date;
        int		gmt_offset;
        I32		gimme = GIMME_V;
	char *		str;
    PPCODE:
        if (gimme == G_SCALAR) {
          str = g_mime_message_delivery_get_rcpt_last_attempt_date_string(delivery, rcpt_index);
	  if (str) {
            XPUSHs(sv_2mortal(newSVpv(str,0)));
	    g_free (str);
	  }
        } else if (gimme == G_ARRAY) {
          g_mime_message_delivery_get_rcpt_last_attempt_date(delivery, rcpt_index, &date, &gmt_offset);
          XPUSHs(sv_2mortal(newSVnv(date)));
          XPUSHs(sv_2mortal(newSViv(gmt_offset)));
        }


void
g_mime_message_delivery_set_rcpt_last_attempt_date_string(delivery, rcpt_index, value)
        MIME::Fast::MessageDelivery	delivery
	int				rcpt_index
	const char *			value

void
g_mime_message_delivery_set_rcpt_last_attempt_date(delivery, rcpt_index, date, gmt_offset)
        MIME::Fast::MessageDelivery	delivery
	int				rcpt_index
	time_t				date
	int				gmt_offset


void
g_mime_message_delivery_set_rcpt_will_retry_until_string(delivery, rcpt_index, value)
        MIME::Fast::MessageDelivery	delivery
	int				rcpt_index
	const char *			value


 #
 # returns scalar string or array (date, gmt_offset)
 #
void
g_mime_message_delivery_get_rcpt_will_retry_until(delivery, rcpt_index)
        MIME::Fast::MessageDelivery	delivery
	int				rcpt_index
    PREINIT:
        time_t		date;
        int		gmt_offset;
        I32		gimme = GIMME_V;
	char *		str;
    PPCODE:
        if (gimme == G_SCALAR) {
          str = g_mime_message_delivery_get_rcpt_will_retry_until_string(delivery, rcpt_index);
	  if (str) {
            XPUSHs(sv_2mortal(newSVpv(str,0)));
	    g_free (str);
	  }
        } else if (gimme == G_ARRAY) {
          g_mime_message_delivery_get_rcpt_will_retry_until(delivery, rcpt_index, &date, &gmt_offset);
          XPUSHs(sv_2mortal(newSVnv(date)));
          XPUSHs(sv_2mortal(newSViv(gmt_offset)));
        }




void
g_mime_message_delivery_set_rcpt_will_retry_until(delivery, rcpt_index, date, gmt_offset)
        MIME::Fast::MessageDelivery	delivery
	int				rcpt_index
	time_t				date
	int				gmt_offset


const char *
g_mime_message_delivery_get_rcpt_header(delivery, rcpt_index, name)
        MIME::Fast::MessageDelivery	delivery
	int				rcpt_index
	const char *			name


void
g_mime_message_delivery_set_rcpt_header(delivery, rcpt_index, name, value)
        MIME::Fast::MessageDelivery	delivery
	int				rcpt_index
	const char *			name
	const char *			value


void
g_mime_message_delivery_remove_rcpt_header(delivery, rcpt_index, name)
        MIME::Fast::MessageDelivery	delivery
	int				rcpt_index
	const char *			name



void
g_mime_message_delivery_status_to_string(status)
	const char *			status
    PREINIT:
	const char *	class_code;
	const char *	class_detail;
    PPCODE:
	class_detail = g_mime_message_delivery_status_to_string(status, &class_code);
	XPUSHs(sv_2mortal(newSVpv(class_code, 0)));
	XPUSHs(sv_2mortal(newSVpv(class_detail, 0)));


MODULE = MIME::Fast		PACKAGE = MIME::Fast::MessageMDN	PREFIX=g_mime_message_mdn_

MIME::Fast::MessageMDN
g_mime_message_part_new(Class)
        char *			Class
    CODE:
    	RETVAL = g_mime_message_mdn_new();
        plist = g_list_prepend(plist, RETVAL);
    OUTPUT:
        RETVAL

# destroy(mdn)
void
DESTROY(mdn)
        MIME::Fast::MessageMDN	mdn
    CODE:
        if (gmime_debug)
          warn("g_mime_message_mdn_DESTROY: 0x%x %s", mdn,
          g_list_find(plist,mdn) ? "(true destroy)" : "(only attempt)");
        if (g_list_find(plist,mdn)) {
          g_mime_object_unref (GMIME_OBJECT (mdn));
          plist = g_list_remove(plist, mdn);
	}

void
g_mime_message_mdn_set_mdn_headers(mdn, svmixed)
        MIME::Fast::MessageMDN	mdn
	SV *			svmixed
    PREINIT:
	SV *			svvalue;
	svtype			svvaltype;
	GMimeHeader		*header;
    CODE:
	svvalue = svmixed;
	if (SvROK(svmixed)) {
	  svvalue = SvRV(svmixed);
	}
	svvaltype = SvTYPE(svvalue);
	if (svvaltype == SVt_PVHV) {
	  HV *		hvarray;
	  I32		keylen;
	  SV *	svtmp, *svval;
	  IV tmp;
	  char *key;

	  hvarray = (HV *)svvalue;
	  header = g_mime_header_new();
	  while ((svval = hv_iternextsv(hvarray, &key, &keylen)) != NULL)
	  {
		  g_mime_header_add(header, key, (const char *)SvPV_nolen(svval));
	  }
	  g_mime_message_mdn_set_mdn_headers(mdn, header);
	} else {
        	croak("Usage: MIME::Fast::MessageDelivery::set_mdn_headers(\%array_of_headers)");
		XSRETURN_UNDEF;
	}


SV *
g_mime_message_mdn_get_mdn_headers(mdn)
        MIME::Fast::MessageMDN	mdn
    PREINIT:
	GMimeHeader *		header;
	struct raw_header *	h;
	HV *			rh;
    CODE:
	header = g_mime_message_mdn_get_mdn_headers(mdn);
	if (!header) {
		XSRETURN_UNDEF;
	}
	rh = (HV *)sv_2mortal((SV *)newHV());
	h = header->headers;
	while (h && h->name) {
		hv_store(rh, h->name, 0, newSVpv(h->value, 0), 0);
		h = h->next;
	}
	g_mime_header_destroy(header);
	RETVAL = newRV((SV *)rh);
    OUTPUT:
	RETVAL


void
g_mime_message_mdn_set_mdn_header(mdn, name, value)
        MIME::Fast::MessageMDN	mdn
	const char *			name
	const char *			value

const char *
g_mime_message_mdn_get_mdn_header(mdn, name)
        MIME::Fast::MessageMDN	mdn
	const char *			name

void
g_mime_message_mdn_remove_mdn_header(mdn, name)
        MIME::Fast::MessageMDN	mdn
	const char *			name


void
g_mime_message_mdn_set_reporting_ua(mdn, value)
        MIME::Fast::MessageMDN	mdn
	const char *			value

const char *
g_mime_message_mdn_get_reporting_ua(mdn)
        MIME::Fast::MessageMDN	mdn


void
g_mime_message_mdn_set_mdn_gateway(mdn, value)
        MIME::Fast::MessageMDN	mdn
	const char *			value

const char *
g_mime_message_mdn_get_mdn_gateway(mdn)
        MIME::Fast::MessageMDN	mdn


void
g_mime_message_mdn_set_original_recipient(mdn, value)
        MIME::Fast::MessageMDN	mdn
	const char *			value

const char *
g_mime_message_mdn_get_original_recipient(mdn)
        MIME::Fast::MessageMDN	mdn


void
g_mime_message_mdn_set_final_recipient(mdn, value)
        MIME::Fast::MessageMDN	mdn
	const char *			value

const char *
g_mime_message_mdn_get_final_recipient(mdn)
        MIME::Fast::MessageMDN	mdn


void
g_mime_message_mdn_set_original_message_id(mdn, value)
        MIME::Fast::MessageMDN	mdn
	const char *			value

const char *
g_mime_message_mdn_get_original_message_id(mdn)
        MIME::Fast::MessageMDN	mdn


void
g_mime_message_mdn_set_disposition(mdn, value)
        MIME::Fast::MessageMDN	mdn
	const char *			value

SV *
g_mime_message_mdn_get_disposition(mdn)
        MIME::Fast::MessageMDN	mdn
    PREINIT:
	char *	textdata;
    CODE:
	textdata = g_mime_message_mdn_get_disposition(mdn);
	if (textdata) {
	  RETVAL = newSVpv(textdata, 0);
	  g_free (textdata);
	} else {
	  XSRETURN_UNDEF;
	}
    OUTPUT:
	RETVAL

# unsupported because const MIME::Fast::MessageMDNDisposition is useless
# g_mime_message_mdn_get_disposition_object(mdn)

void
g_mime_message_mdn_set_disposition_object(mdn, mdn_disposition)
        MIME::Fast::MessageMDN	mdn
	MIME::Fast::MessageMDNDisposition	mdn_disposition
    CODE:
	g_mime_message_mdn_set_disposition_object(mdn, mdn_disposition);
        plist = g_list_remove(plist, mdn_disposition);


void
g_mime_message_mdn_set_failure(mdn, value)
        MIME::Fast::MessageMDN	mdn
	const char *			value

const char *
g_mime_message_mdn_get_failure(mdn)
        MIME::Fast::MessageMDN	mdn


void
g_mime_message_mdn_set_error(mdn, value)
        MIME::Fast::MessageMDN	mdn
	const char *			value

const char *
g_mime_message_mdn_get_error(mdn)
        MIME::Fast::MessageMDN	mdn


void
g_mime_message_mdn_set_warning(mdn, value)
        MIME::Fast::MessageMDN	mdn
	const char *			value

const char *
g_mime_message_mdn_get_warning(mdn)
        MIME::Fast::MessageMDN	mdn


MODULE = MIME::Fast		PACKAGE = MIME::Fast::MessageMDNDisposition	PREFIX=g_mime_message_mdn_disposition_

MIME::Fast::MessageMDNDisposition
g_mime_message_mdn_disposition_new(Class, disposition = 0)
    CASE: items == 1
        char *		Class
    CODE:
        RETVAL = g_mime_message_mdn_disposition_new ();
        plist = g_list_prepend(plist, RETVAL);
    OUTPUT:
        RETVAL
    CASE: items == 2
        char *		Class
	const char *	disposition
    CODE:
        RETVAL = g_mime_message_mdn_disposition_new_from_string (disposition);
        plist = g_list_prepend(plist, RETVAL);
    OUTPUT:
        RETVAL

# destroy(mdn_disposition)
void
DESTROY(mdn_disposition)
        MIME::Fast::MessageMDNDisposition	mdn_disposition
    CODE:
        if (gmime_debug)
          warn("g_mime_message_mdn_disposition_DESTROY: 0x%x", mdn_disposition,
	  g_list_find(plist,mdn_disposition) ? "(true destroy)" : "(only attempt)");
	if (g_list_find(plist,mdn_disposition)) {
	  g_mime_message_mdn_disposition_destroy (mdn_disposition);
	  plist = g_list_remove(plist, mdn_disposition);
	}

void
g_mime_message_mdn_disposition_set_action_mode(mdn_disposition, value)
        MIME::Fast::MessageMDNDisposition	mdn_disposition
	const char *		value

const char *
g_mime_message_mdn_disposition_get_action_mode(mdn_disposition)
        MIME::Fast::MessageMDNDisposition	mdn_disposition


void
g_mime_message_mdn_disposition_set_sending_mode(mdn_disposition, value)
        MIME::Fast::MessageMDNDisposition	mdn_disposition
	const char *		value

const char *
g_mime_message_mdn_disposition_get_sending_mode(mdn_disposition)
        MIME::Fast::MessageMDNDisposition	mdn_disposition


void
g_mime_message_mdn_disposition_set_type(mdn_disposition, value)
        MIME::Fast::MessageMDNDisposition	mdn_disposition
	const char *		value

const char *
g_mime_message_mdn_disposition_get_type(mdn_disposition)
        MIME::Fast::MessageMDNDisposition	mdn_disposition


void
g_mime_message_mdn_disposition_set_modifier(mdn_disposition, value)
        MIME::Fast::MessageMDNDisposition	mdn_disposition
	const char *		value

const char *
g_mime_message_mdn_disposition_get_modifier(mdn_disposition)
        MIME::Fast::MessageMDNDisposition	mdn_disposition


SV *
g_mime_message_mdn_disposition_header(mdn_disposition, fold = 0)
        MIME::Fast::MessageMDNDisposition	mdn_disposition
	int			fold
    PREINIT:
	char *	textdata;
    CODE:
	textdata = g_mime_message_mdn_disposition_header(mdn_disposition, fold);
	if (textdata) {
	  RETVAL = newSVpv(textdata, 0);
	  g_free (textdata);
	} else {
	  XSRETURN_UNDEF;
	}
    OUTPUT:
	RETVAL

#endif

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
        char *		name
    CODE:
        RETVAL = internet_address_new_group(name);
        plist = g_list_prepend(plist, RETVAL);
    OUTPUT:
        RETVAL
    CASE: items == 3
        char *		Class
        char *		name
        char *		address
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
          internet_address_unref(ia);
          plist = g_list_remove(plist, ia);
        }

AV *
internet_address_parse_string(str)
        const char *		str
    PREINIT:
        InternetAddressList *		addrlist;
        AV * 		retav;
    CODE:
        addrlist = internet_address_parse_string(str);
        while (addrlist) {
          SV * address = newSViv(0);
          sv_setref_pv(address, "MIME::Fast::InternetAddress", (MIME__Fast__InternetAddress)(addrlist->address));
          av_push(retav, address);
          addrlist = addrlist->next;
        }
        RETVAL = retav;
    OUTPUT:
        RETVAL


void
interface_ia_set(ia, value)
        MIME::Fast::InternetAddress	ia
	char *				value
    INTERFACE_MACRO:
	XSINTERFACE_FUNC
	XSINTERFACE_FUNC_MIMEFAST_IA_SET
    INTERFACE:
	set_name
	set_addr

 #
 # Unsupported functions:
 # internet_address_list_prepend
 # internet_address_list_append
 # internet_address_list_concat
 #
 
SV *
internet_address_to_string(ia, encode = TRUE)
        MIME::Fast::InternetAddress	ia
        gboolean		encode
    PREINIT:
	char *		textdata;
    CODE:
	textdata = internet_address_to_string(ia, encode);
	if (textdata == NULL)
	  XSRETURN_UNDEF;
	RETVAL = newSVpv(textdata, 0);
    OUTPUT:
	RETVAL

void
internet_address_set_group(ia, ...)
        MIME::Fast::InternetAddress	ia
    PREINIT:
        MIME__Fast__InternetAddress	addr;
        InternetAddressList *		addrlist = NULL;
        int			i;
    CODE:
        if (items < 2) {
          croak("Usage: internet_address_set_group(InternetAddr, [InternetAddr]+");
	  XSRETURN_UNDEF;
        }
        for (i=items - 1; i>0; --i) {
          /* retrieve each address from the perl array */
          if (sv_derived_from(ST(items - i), "MIME::Fast::InternetAddress")) {
            IV tmp = SvIV((SV*)SvRV(ST(items - i)));
            addr = INT2PTR(MIME__Fast__InternetAddress, tmp);
          } else
            croak("Usage: internet_address_set_group(InternetAddr, [InternetAddr]+");
          if (addr)
            internet_address_list_append (addrlist, addr);
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
g_mime_charset_init(mime_charset)
    MIME::Fast::Charset mime_charset

const char *
g_mime_charset_locale_name()

 # needed only for non iso8859-1 locales
void
g_mime_charset_map_init()

const char *
g_mime_charset_name(charset)
	const char *	charset

void
g_mime_charset_step(mime_charset, svtext)
	MIME::Fast::Charset	mime_charset
        SV *			svtext
    PREINIT:
	char *	data;
	STRLEN	len;
    CODE:
        data = (char *)SvPV(svtext, len);
	g_mime_charset_step(mime_charset, data, len);

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
        const char *		Class
        MIME::Fast::Stream	mime_stream
        MIME::Fast::PartEncodingType		encoding
    CODE:
    	RETVAL = g_mime_data_wrapper_new_with_stream(mime_stream, encoding);
        plist = g_list_prepend(plist, RETVAL);
    OUTPUT:
    	RETVAL

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
        const char *	Class
        SV *		svmixed
    PREINIT:
        STRLEN		len;
        char *		data;
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
	    PerlIO *pio;
	    FILE *fp;
	    int fd;

	    pio = IoIFP(sv_2io(svval));
	    if (!pio || !(fp = PerlIO_findFILE(pio))) {
	      croak("MIME::Fast::Stream::new: the argument you gave is not a FILE pointer");
	    }
	    
	    fd = dup(fileno(fp));
	    if (fd == -1)
	      croak("MIME::Fast::Stream::new: Can not duplicate a FILE pointer");

            // mime_stream = g_mime_stream_file_new(fp);
            mime_stream = g_mime_stream_fs_new(fd);
	    if (!mime_stream) {
	      close(fd);
	      XSRETURN_UNDEF;
            }
	    // g_mime_stream_file_set_owner (mime_stream, FALSE);
	  } else if (svvaltype == SVt_PVMG) { // possible STDIN/STDOUT etc.
            int fd0 = (int)SvIV( svval );
	    int fd;

	    if (fd0 < 0 || (fd = dup(fd0)) == -1)
	      croak("MIME::Fast::Stream::new: Can not duplicate a FILE pointer");

            mime_stream = g_mime_stream_fs_new(fd);
	    if (!mime_stream) {
	      close(fd);
	      XSRETURN_UNDEF;
            }
	    // g_mime_stream_fs_set_owner (mime_stream, FALSE);
          } else if (SvPOK(svval)) {
            data = (char *)SvPV(svmixed, len);
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
        const char *	Class
        SV *		svmixed
        off_t		start
        off_t		end
    PREINIT:
        STRLEN		len;
        char *		data;
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
	    PerlIO *pio;
	    FILE *fp;
	    int fd;

	    pio = IoIFP(sv_2io(svval));
	    if (!pio || !(fp = PerlIO_findFILE(pio))) {
	      croak("MIME::Fast::Stream::new: the argument you gave is not a FILE pointer");
	    }
	    
	    fd = dup(fileno(fp));
	    if (fd == -1)
	      croak("MIME::Fast::Stream::new: Can not duplicate a FILE pointer");


            // mime_stream = g_mime_stream_file_new_with_bounds(fp, start, end);
            mime_stream = g_mime_stream_fs_new_with_bounds(fd, start, end);
	    if (!mime_stream) {
	      close(fd);
	      XSRETURN_UNDEF;
            }
	    // g_mime_stream_file_set_owner (mime_stream, FALSE);
	  } else if (svvaltype == SVt_PVMG) { // possible STDIN/STDOUT etc.
            int fd0 = (int)SvIV( svval );
	    int fd;

	    if (fd0 < 0 || (fd = dup(fd0)) == -1)
	      croak("MIME::Fast::Stream::new: Can not duplicate a FILE pointer");

            mime_stream = g_mime_stream_fs_new_with_bounds(fd, start, end);
	    if (!mime_stream) {
	      close(fd);
	      XSRETURN_UNDEF;
            }
	    // g_mime_stream_fs_set_owner (mime_stream, FALSE);

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
	    if (GMIME_IS_STREAM_FILE(mime_stream)) {
		GMimeStreamFile *	fstream;

		fstream = GMIME_STREAM_FILE (mime_stream);
		fstream->owner = FALSE;
		fstream->fp = NULL;
	    }
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
        char *			str
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

ssize_t
g_mime_stream_write_to_stream(mime_stream_src, svstream)
        MIME::Fast::Stream	mime_stream_src
	SV *			svstream
    PREINIT:
        GMimeStream *		mime_stream_dst;
    CODE:
	if (sv_derived_from(ST(1), "MIME::Fast::Stream")) {
	    IV tmp = SvIV((SV*)SvRV(ST(1)));
	    mime_stream_dst = INT2PTR(MIME__Fast__Stream,tmp);
	}
	else
	    Perl_croak(aTHX_ "mime_stream is not of type MIME::Fast::Stream");
	
        RETVAL = g_mime_stream_write_to_stream(mime_stream_src, mime_stream_dst);
    OUTPUT:
        RETVAL


MODULE = MIME::Fast		PACKAGE = MIME::Fast::Filter		PREFIX=g_mime_filter_

void
DESTROY(mime_filter)
        MIME::Fast::Filter	mime_filter
    CODE:
        if (gmime_debug)
          warn("g_mime_filter_DESTROY: 0x%x %s", mime_filter,
	  g_list_find(plist,mime_filter) ? "(true destroy)" : "(only attempt)");
	if (g_list_find(plist,mime_filter)) {
	  g_object_unref (mime_filter);
	  plist = g_list_remove(plist, mime_filter);
	}

 #
 # Copies @filter into a new GMimeFilter object.
 #
MIME::Fast::Filter
g_mime_filter_copy (filter);
	MIME::Fast::Filter	filter
    CODE:
	RETVAL = g_mime_filter_copy (filter);
	plist = g_list_prepend (plist, RETVAL);
    OUTPUT:
	RETVAL

void
g_mime_filter_reset (filter)
	MIME::Fast::Filter	filter

void
g_mime_filter_set_size (filter, size, keep)
	MIME::Fast::Filter	filter
	size_t			size
	gboolean		keep


MODULE = MIME::Fast		PACKAGE = MIME::Fast::Filter::Basic	PREFIX=g_mime_filter_basic_

MIME::Fast::Filter::Basic
g_mime_filter_basic_new(Class, type)
	const char *			Class
        int			type
    CODE:
	RETVAL = GMIME_FILTER_BASIC(g_mime_filter_basic_new_type (type));
	plist = g_list_prepend (plist, RETVAL);
    OUTPUT:
	RETVAL


MODULE = MIME::Fast		PACKAGE = MIME::Fast::Filter::Best	PREFIX=g_mime_filter_best_

MIME::Fast::Filter::Best
g_mime_filter_best_new(Class, flags)
	const char *		Class
	unsigned int		flags
    CODE:
	RETVAL = GMIME_FILTER_BEST(g_mime_filter_best_new (flags));
	plist = g_list_prepend (plist, RETVAL);
    OUTPUT:
	RETVAL

const char *
g_mime_filter_best_charset(mime_filter_best)
	MIME::Fast::Filter::Best	mime_filter_best

MIME::Fast::PartEncodingType
g_mime_filter_best_encoding(mime_filter_best, required)
	MIME::Fast::Filter::Best	mime_filter_best
	MIME::Fast::BestEncoding	required


MODULE = MIME::Fast		PACKAGE = MIME::Fast::Filter::Charset	PREFIX=g_mime_filter_charset_

MIME::Fast::Filter::Charset
g_mime_filter_charset_new(Class, from_charset, to_charset)
	const char *		Class
	const char *		from_charset
	const char *		to_charset
    CODE:
	RETVAL = GMIME_FILTER_CHARSET(g_mime_filter_charset_new (from_charset, to_charset));
	plist = g_list_prepend (plist, RETVAL);
    OUTPUT:
	RETVAL


MODULE = MIME::Fast		PACKAGE = MIME::Fast::Filter::CRLF	PREFIX=g_mime_filter_crlf_

MIME::Fast::Filter::CRLF
g_mime_filter_crlf_new(Class, direction, mode)
	const char *		Class
        int			direction
        int			mode
    CODE:
	RETVAL = GMIME_FILTER_CRLF(g_mime_filter_crlf_new (direction, mode));
	plist = g_list_prepend (plist, RETVAL);
    OUTPUT:
	RETVAL


MODULE = MIME::Fast		PACKAGE = MIME::Fast::Filter::From	PREFIX=g_mime_filter_from_

MIME::Fast::Filter::From
g_mime_filter_from_new(Class, mode)
	const char *			Class
        MIME::Fast::FilterFromMode	mode
    CODE:
	RETVAL = GMIME_FILTER_FROM(g_mime_filter_from_new (mode));
	plist = g_list_prepend (plist, RETVAL);
    OUTPUT:
	RETVAL


#if GMIME_CHECK_VERSION_2_0_9

MODULE = MIME::Fast		PACKAGE = MIME::Fast::Filter::Func	PREFIX=g_mime_filter_func_

 # unsupported:
 # g_mime_filter_filter
 # g_mime_filter_complete
 # g_mime_filter_backup

MIME::Fast::Filter::Func
g_mime_filter_func_new(Class, svstep, svcomplete = 0, svsizeout = 0, svdata = 0)
    CASE: items == 5
    	const char *		Class
        SV *			svstep
	SV *			svcomplete
	SV *			svsizeout
        SV *			svdata
    PREINIT:
	struct _user_data_sv    *data;
    CODE:
	data = g_new0 (struct _user_data_sv, 1);
	data->svuser_data  = svdata;
	data->svfunc  = svstep;
	data->svfunc_complete = svcomplete;
	data->svfunc_sizeout  = svsizeout;
	RETVAL = g_mime_filter_func_new (call_filter_step_func,
			call_filter_complete_func, call_filter_sizeout_func, data);
	plist = g_list_prepend (plist, RETVAL);
    OUTPUT:
	RETVAL
    CASE: items == 4
    	const char *		Class
        SV *			svstep
	SV *			svcomplete
	SV *			svsizeout
    PREINIT:
	struct _user_data_sv    *data;
    CODE:
	data = g_new0 (struct _user_data_sv, 1);
	data->svfunc  = svstep;
	data->svfunc_complete = svcomplete;
	data->svfunc_sizeout  = svsizeout;
	RETVAL = g_mime_filter_func_new(call_filter_step_func,
			call_filter_complete_func, call_filter_sizeout_func, data);
	plist = g_list_prepend (plist, RETVAL);
    OUTPUT:
	RETVAL
    CASE: items == 3
    	const char *		Class
        SV *			svstep
	SV *			svcomplete
    PREINIT:
	struct _user_data_sv    *data;
    CODE:
	data = g_new0 (struct _user_data_sv, 1);
	data->svfunc  = svstep;
	data->svfunc_complete = svcomplete;
	RETVAL = g_mime_filter_func_new(call_filter_step_func,
			call_filter_complete_func, NULL, data);
	plist = g_list_prepend (plist, RETVAL);
    OUTPUT:
	RETVAL
    CASE: items == 2
    	const char *		Class
        SV *			svstep
    PREINIT:
	struct _user_data_sv    *data;
    CODE:
	data = g_new0 (struct _user_data_sv, 1);
	data->svfunc  = svstep;
	data->svfunc_complete = svstep;
	RETVAL = g_mime_filter_func_new(call_filter_step_func,
			call_filter_complete_func, NULL, data);
	plist = g_list_prepend (plist, RETVAL);
    OUTPUT:
	RETVAL

#endif

MODULE = MIME::Fast		PACKAGE = MIME::Fast::Filter::HTML	PREFIX=g_mime_filter_html_

MIME::Fast::Filter::HTML
g_mime_filter_html_new(Class, flags, colour)
	const char *		Class
	guint32			flags
	guint32			colour
    CODE:
	RETVAL = GMIME_FILTER_HTML(g_mime_filter_html_new(flags, colour));
	plist = g_list_prepend (plist, RETVAL);
    OUTPUT:
	RETVAL


MODULE = MIME::Fast		PACKAGE = MIME::Fast::Filter::Md5	PREFIX=g_mime_filter_md5_

MIME::Fast::Filter::Md5
g_mime_filter_md5_new(Class)
	const char *		Class
    CODE:
	RETVAL = GMIME_FILTER_MD5(g_mime_filter_md5_new());
	plist = g_list_prepend (plist, RETVAL);
    OUTPUT:
	RETVAL

SV *
g_mime_filter_md5_get_digest(mime_filter_md5)
	MIME::Fast::Filter::Md5	mime_filter_md5
    PREINIT:
	unsigned char md5_digest[16];
    CODE:
	md5_digest[0] = '\0';
	g_mime_filter_md5_get_digest (mime_filter_md5, md5_digest);
	RETVAL = newSVpv(md5_digest, 0);
    OUTPUT:
	RETVAL


MODULE = MIME::Fast		PACKAGE = MIME::Fast::Filter::Strip	PREFIX=g_mime_filter_strip_

MIME::Fast::Filter::Strip
g_mime_filter_strip_new(Class)
	const char *		Class
    CODE:
	RETVAL = GMIME_FILTER_STRIP(g_mime_filter_strip_new());
	plist = g_list_prepend (plist, RETVAL);
    OUTPUT:
	RETVAL


MODULE = MIME::Fast		PACKAGE = MIME::Fast::Filter::Yenc	PREFIX=g_mime_filter_yenc_

MIME::Fast::Filter::Yenc
g_mime_filter_yenc_new(Class, direction)
	const char *			Class
	Mime::Fast::FilterYencDirection	direction
    CODE:
	RETVAL = GMIME_FILTER_YENC(g_mime_filter_yenc_new(direction));
	plist = g_list_prepend (plist, RETVAL);
    OUTPUT:
	RETVAL

 # unsupported (yet):
 # g_mime_filter_yenc_get_crc etc.


MODULE = MIME::Fast		PACKAGE = MIME::Fast::StreamFilter	PREFIX=g_mime_stream_filter_

MIME::Fast::StreamFilter
g_mime_stream_filter_new(Class, mime_stream)
	const char *			Class
	MIME::Fast::Stream		mime_stream
    CODE:
	RETVAL = GMIME_STREAM_FILTER(g_mime_stream_filter_new_with_stream (mime_stream));
	plist = g_list_prepend(plist, RETVAL);
    OUTPUT:
	RETVAL

int
g_mime_stream_filter_add(mime_streamfilter, mime_filter)
	MIME::Fast::StreamFilter	mime_streamfilter
	MIME::Fast::Filter		mime_filter

void
g_mime_stream_filter_remove(mime_streamfilter, filter_num)
	MIME::Fast::StreamFilter	mime_streamfilter
	int				filter_num


MODULE = MIME::Fast		PACKAGE = MIME::Fast::Parser		PREFIX=g_mime_parser_

MIME::Fast::Parser
g_mime_parser_new(Class = "MIME::Fast::Parser", mime_stream = 0)
    CASE: items == 1
	char *			Class;
    CODE:
	RETVAL = g_mime_parser_new();
	plist = g_list_prepend(plist, RETVAL);
    OUTPUT:
        RETVAL
    CASE: items == 2
	char *			Class;
	MIME::Fast::Stream	mime_stream;
    CODE:
	RETVAL = g_mime_parser_new_with_stream(mime_stream);
	plist = g_list_prepend(plist, RETVAL);
    OUTPUT:
        RETVAL

 # destroy(mime_parser)
void
DESTROY(mime_parser)
        MIME::Fast::Parser	mime_parser
    CODE:
        if (gmime_debug)
          warn("g_mime_parser_DESTROY: 0x%x %s", mime_parser,
	  g_list_find(plist,mime_parser) ? "(true destroy)" : "(only attempt)");
	if (g_list_find(plist,mime_parser)) {
	  g_object_unref (mime_parser);
	  plist = g_list_remove(plist, mime_parser);
	}


MIME::Fast::Message
g_mime_parser_construct_message(svmixed)
        SV *		svmixed
    PREINIT:
        STRLEN		len;
        char *		data;
        GMimeMessage	*mime_msg = NULL;
        GMimeStream	*mime_stream = NULL;
        GMimeParser *parser = NULL;
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
                parser = g_mime_parser_new_with_stream(mime_stream);
          	mime_msg = g_mime_parser_construct_message(parser);
                g_mime_stream_unref(mime_stream);
		g_object_unref (parser);
          } else if (sv_derived_from(svmixed, "MIME::Fast::Stream")) {
          	IV tmp = SvIV((SV*)SvRV(svmixed));

        	mime_stream = INT2PTR(MIME__Fast__Stream,tmp);

                parser = g_mime_parser_new_with_stream(mime_stream);
          	mime_msg = g_mime_parser_construct_message(parser);
		g_object_unref (parser);
          } else if (sv_derived_from(svmixed, "MIME::Fast::Parser")) {
          	IV tmp = SvIV((SV*)SvRV(svmixed));

        	parser = INT2PTR(MIME__Fast__Parser,tmp);
          	mime_msg = g_mime_parser_construct_message(parser);
          }
          svval = SvRV(svmixed);
        }
        svvaltype = SvTYPE(svval);

        if (mime_stream == NULL) {
          if (svvaltype == SVt_PVGV) { // possible FILE * handle
            //FILE *  fp = PerlIO_findFILE(IoIFP(sv_2io(svval)));
	    //int fd = dup(fileno(fp));
	    PerlIO *pio;
	    FILE *fp;
	    int fd;

	    pio = IoIFP(sv_2io(svval));
	    if (!pio || !(fp = PerlIO_findFILE(pio))) {
	      croak("MIME::Fast::Parser::construct_message: the argument you gave is not a FILE pointer");
	    }
	    
	    fd = dup(fileno(fp));
	    if (fd == -1)
	      croak("MIME::Fast::Parser::construct_message: Can not duplicate a FILE pointer");

            // mime_stream = g_mime_stream_file_new(fp);
	    // g_mime_stream_file_set_owner (mime_stream, FALSE);
            mime_stream = g_mime_stream_fs_new(fd);
	    if (!mime_stream) {
	      close(fd);
	      XSRETURN_UNDEF;
            }
            parser = g_mime_parser_new_with_stream(mime_stream);
            mime_msg = g_mime_parser_construct_message(parser);
            g_mime_stream_unref(mime_stream);
	    g_object_unref (parser);
	  } else if (svvaltype == SVt_PVMG) { // possible STDIN/STDOUT etc.
            int fd0 = (int)SvIV( svval );
	    int fd;

	    if (fd0 < 0 || (fd = dup(fd0)) == -1)
	      croak("MIME::Fast::Parser::construct_message: Can not duplicate a FILE pointer");
            mime_stream = g_mime_stream_fs_new(fd);
	    if (!mime_stream) {
	      close(fd);
	      XSRETURN_UNDEF;
            }
            parser = g_mime_parser_new_with_stream(mime_stream);
            mime_msg = g_mime_parser_construct_message(parser);
            g_mime_stream_unref(mime_stream);
	    g_object_unref (parser);
          } else if (SvPOK(svval)) {
            data = (char *)SvPV(svval, len);
            mime_stream = g_mime_stream_mem_new_with_buffer(data,len);
            parser = g_mime_parser_new_with_stream(mime_stream);
            mime_msg = g_mime_parser_construct_message(parser);
            g_mime_stream_unref(mime_stream);
	    g_object_unref (parser);
          } else {
            croak("construct_message: Unknown type: %d", (int)svvaltype);
          }
        }
    	
        RETVAL = mime_msg;
	if (gmime_debug)
          warn("g_mime_parser_construct_message: 0x%x\n", RETVAL);
        plist = g_list_prepend(plist, RETVAL);
    OUTPUT:
        RETVAL

SV *
g_mime_parser_construct_part(svmixed)
        SV *		svmixed
    PREINIT:
        STRLEN		len;
        char *		data;
        GMimePart	*mime_part = NULL;
        GMimeObject	*mime_object = NULL;
        GMimeStream	*mime_stream = NULL;
        GMimeParser *parser = NULL;
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
                parser = g_mime_parser_new_with_stream(mime_stream);
          	mime_object = g_mime_parser_construct_part(parser);
                g_mime_stream_unref(mime_stream);
		g_object_unref (parser);
          } else if (sv_derived_from(svmixed, "MIME::Fast::Stream")) {
          	IV tmp = SvIV((SV*)SvRV(svmixed));

        	mime_stream = INT2PTR(MIME__Fast__Stream,tmp);
                parser = g_mime_parser_new_with_stream(mime_stream);
          	mime_object = g_mime_parser_construct_part(parser);
		g_object_unref (parser);
          } else if (sv_derived_from(svmixed, "MIME::Fast::Parser")) {
          	IV tmp = SvIV((SV*)SvRV(svmixed));

        	parser = INT2PTR(MIME__Fast__Parser,tmp);
          	mime_object = g_mime_parser_construct_part(parser);
          }
          svval = SvRV(svmixed);
        }
        svvaltype = SvTYPE(svval);

        if (mime_stream == NULL) {
          if (svvaltype == SVt_PVGV) { // possible FILE * handle
	    PerlIO *pio;
	    FILE *fp;
	    int fd;

	    pio = IoIFP(sv_2io(svval));
	    if (!pio || !(fp = PerlIO_findFILE(pio))) {
	      croak("MIME::Fast::Parser::construct_part: the argument you gave is not a FILE pointer");
	    }
	    
	    fd = dup(fileno(fp));
	    if (fd == -1)
	      croak("MIME::Fast::Parser::construct_part: Can not duplicate a FILE pointer");
            //mime_stream = g_mime_stream_file_new(fp);
            mime_stream = g_mime_stream_fs_new(fd);
	    if (!mime_stream) {
	      close(fd);
	      XSRETURN_UNDEF;
            }
	    // g_mime_stream_file_set_owner (mime_stream, FALSE);
            parser = g_mime_parser_new_with_stream(mime_stream);
            mime_object = g_mime_parser_construct_part(parser);
            g_mime_stream_unref(mime_stream);
	    g_object_unref (parser);
	  } else if (svvaltype == SVt_PVMG) { // possible STDIN/STDOUT etc.
            int fd0 = (int)SvIV( svval );
	    int fd;

	    if (fd0 < 0 || (fd = dup(fd0)) == -1)
	      croak("MIME::Fast::Parser::construct_part: Can not duplicate a FILE pointer");

            mime_stream = g_mime_stream_fs_new(fd);
	    if (!mime_stream) {
		close(fd);
		XSRETURN_UNDEF;
	    }
            parser = g_mime_parser_new_with_stream(mime_stream);
            mime_object = g_mime_parser_construct_part(parser);
            g_mime_stream_unref(mime_stream);
	    g_object_unref (parser);
          } else if (SvPOK(svval)) {
            data = (char *)SvPV(svmixed, len);
            mime_stream = g_mime_stream_mem_new_with_buffer(data,len);
            parser = g_mime_parser_new_with_stream(mime_stream);
            mime_object = g_mime_parser_construct_part(parser);
            g_mime_stream_unref(mime_stream);
	    g_object_unref (parser);
          } else {
            croak("construct_part: Unknown type: %d", (int)svvaltype);
          }
        }
    	
	RETVAL = newSViv(0);

        if (GMIME_IS_MULTIPART(mime_object))
	  sv_setref_pv(RETVAL, "MIME::Fast::MultiPart", (MIME__Fast__MultiPart)mime_object);
	else if (GMIME_IS_MESSAGE_PART(mime_object))
	  sv_setref_pv(RETVAL, "MIME::Fast::MessagePart", (MIME__Fast__MessagePart)mime_object);
	else if (GMIME_IS_MESSAGE_PARTIAL(mime_object))
	  sv_setref_pv(RETVAL, "MIME::Fast::MessagePartial", (MIME__Fast__MessagePartial)mime_object);
	else if (GMIME_IS_PART(mime_object))
	  sv_setref_pv(RETVAL, "MIME::Fast::Part", (MIME__Fast__Part)mime_object);
	else
	  die("g_mime_parser_construct_part: unknown type of object: 0x%x", mime_object);
        
	if (gmime_debug)
          warn("g_mime_parser_construct_part: 0x%x mo=%p\n", RETVAL, mime_object);
        plist = g_list_prepend(plist, mime_object);
    OUTPUT:
        RETVAL

void
g_mime_parser_init_with_stream(parser, mime_stream)
	MIME::Fast::Parser	parser
	MIME::Fast::Stream	mime_stream

void
g_mime_parser_set_scan_from(parser, scan_from)
	MIME::Fast::Parser	parser
	gboolean		scan_from

gboolean
g_mime_parser_get_scan_from(parser)
	MIME::Fast::Parser	parser

 # position
off_t
g_mime_parser_tell(parser)
	MIME::Fast::Parser	parser

gboolean
g_mime_parser_eos(parser)
	MIME::Fast::Parser	parser

SV *
g_mime_parser_get_from(parser)
	MIME::Fast::Parser	parser
    PREINIT:
	char *		textdata = NULL;
    CODE:
	textdata = g_mime_parser_get_from(parser);
	if (textdata == NULL)
	  XSRETURN_UNDEF;
	RETVAL = newSVpv(textdata, 0);
    OUTPUT:
	RETVAL

off_t
g_mime_parser_get_from_offset(parser)
	MIME::Fast::Parser	parser

MODULE = MIME::Fast		PACKAGE = MIME::Fast::Disposition	PREFIX=g_mime_disposition_

MIME::Fast::Disposition
g_mime_disposition_new(Class, disposition)
        char *		Class
	const char *	disposition
    CODE:
        RETVAL = g_mime_disposition_new (disposition);
        plist = g_list_prepend(plist, RETVAL);
    OUTPUT:
        RETVAL

# destroy(mime_disposition)
void
DESTROY(mime_disposition)
        MIME::Fast::Disposition	mime_disposition
    CODE:
        if (gmime_debug)
          warn("g_mime_disposition_DESTROY: 0x%x %s", mime_disposition,
	  g_list_find(plist,mime_disposition) ? "(true destroy)" : "(only attempt)");
	if (g_list_find(plist,mime_disposition)) {
	  g_mime_disposition_destroy (mime_disposition);
	  plist = g_list_remove(plist, mime_disposition);
	}

void
g_mime_disposition_set(mime_disposition, value)
	MIME::Fast::Disposition	mime_disposition
	const char *		value

const char *
g_mime_disposition_get(mime_disposition)
	MIME::Fast::Disposition	mime_disposition

void
g_mime_disposition_add_parameter(mime_disposition, attribute, value)
	MIME::Fast::Disposition	mime_disposition
	const char *		attribute
	const char *		value

const char *
g_mime_disposition_get_parameter(mime_disposition, attribute)
	MIME::Fast::Disposition	mime_disposition
	const char *		attribute

SV *
g_mime_disposition_header(mime_disposition, fold)
	MIME::Fast::Disposition	mime_disposition
	gboolean		fold
    PREINIT:
        char *		out = NULL;
    CODE:
        out = g_mime_disposition_header(mime_disposition, fold);
        if (out) {
          RETVAL = newSVpvn(out,0);
          g_free(out);
        } else
          RETVAL = &PL_sv_undef;
    OUTPUT:
        RETVAL


MODULE = MIME::Fast		PACKAGE = MIME::Fast::Utils		PREFIX=g_mime_utils_

# date
time_t
g_mime_utils_header_decode_date(in, saveoffset)
        const char *	in
        gint 		&saveoffset
    OUTPUT:
        saveoffset

SV *
g_mime_utils_header_format_date(time, offset)
        time_t		time
        gint		offset
    PREINIT:
        char *		out = NULL;
    CODE:
        out = g_mime_utils_header_format_date(time, offset);
        if (out) {
          RETVAL = newSVpvn(out,0);
          g_free(out);
        } else
          RETVAL = &PL_sv_undef;
    OUTPUT:
        RETVAL


SV *
g_mime_utils_generate_message_id(fqdn)
	const char *	fqdn
    PREINIT:
        char *		out = NULL;
    CODE:
	out = g_mime_utils_generate_message_id(fqdn);
	if (!out)
	  XSRETURN_UNDEF;
	RETVAL = newSVpv(out, 0);
	g_free(out);
    OUTPUT:
        RETVAL


SV *
g_mime_utils_decode_message_id(message_id)
	const char *	message_id
    PREINIT:
        char *		out = NULL;
    CODE:
	out = g_mime_utils_decode_message_id(message_id);
	if (!out)
	  XSRETURN_UNDEF;
	RETVAL = newSVpv(out, 0);
	g_free(out);
    OUTPUT:
        RETVAL

# headers
SV *
g_mime_utils_header_fold(in)
        const char *	in
    PREINIT:
        char *		out = NULL;
    CODE:
        out = g_mime_utils_header_fold(in);
        if (out) {
          RETVAL = newSVpvn(out,0);
          g_free(out);
        } else
          RETVAL = &PL_sv_undef;
    OUTPUT:
        RETVAL
        				    

# not implemented g_mime_utils_header_printf()

# quote
SV *
g_mime_utils_quote_string(in)
        const char *	in
    PREINIT:
        char *		out = NULL;
    CODE:
        out = g_mime_utils_quote_string(in);
	if (gmime_debug)
          warn("In=%s Out=%s\n", in, out);
        if (out) {
          RETVAL = newSVpv(out, 0);
          g_free(out);
        } else
          RETVAL = &PL_sv_undef;
    OUTPUT:
        RETVAL

void
g_mime_utils_unquote_string(str)
        char *		str
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

char *
g_mime_utils_8bit_header_decode(in)
        const guchar *	in

char *
g_mime_utils_8bit_header_encode(in)
        const guchar *	in

char *
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

INCLUDE: Fast-Hash.xs

