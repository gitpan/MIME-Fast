
/* known header field types */
enum {
        HEADER_FROM = 0,
        HEADER_REPLY_TO,
        HEADER_TO,
        HEADER_CC,
        HEADER_BCC,
        HEADER_SUBJECT,
        HEADER_DATE,
        HEADER_MESSAGE_ID,
        HEADER_UNKNOWN
};

/* appropriate header field values */
const static char *fields[] = {
        "From",
        "Reply-To",
        "To",
        "Cc",
        "Bcc",
        "Subject",
        "Date",
        "Message-Id",
        NULL
};

/* return number of fields removed from the header of message */
static int
local_header_remove(GMimeHeader *header, const char *field)
{
  struct raw_header *h, *nexth, *prevh;
  int deleted = 0;

  g_mime_header_remove(header, field);
  h = header->headers;
  prevh = NULL;
  while (h) {
    nexth = h->next;
    if (!g_strncasecmp(h->name, field, strlen(field))) {
      if (header->headers == h) {
        header->headers = nexth;
      }
      if (prevh)
        prevh->next = nexth;
      g_free(h->name);
      g_free(h->value);
      g_free(h);
      ++deleted;
    } else {
      prevh = h;
    }
    h = nexth;
  }
  return(deleted);
}

static GList *
local_message_get_header(GMimeMessage *message, const char *field)
{
    GMimeHeader *header;
    struct raw_header *h;
    GList *	gret = NULL;

    if (field == NULL)
	return NULL;
    h = GMIME_OBJECT(message)->headers->headers;
    while (h) {
	if (h->value && !g_strncasecmp(field, h->name, strlen(field))) {
	    gret = g_list_prepend(gret, g_strdup(h->value));
	    if (gmime_debug)
	    warn("Looking for %s => %s\n", field, h->value);
	}
        h = h->next;
    }
    return gret;
}



/**
* internal_recipients_destroy: static function - destroys recipient list
**/
static void
internal_recipients_destroy (GList *recipients)
{
	if (recipients) {
		GList *recipient;
		
		recipient = recipients;
		while (recipient) {
			internet_address_unref (recipient->data);
			recipient = recipient->next;
		}
		
		g_list_free (recipients);
	}
}
/**
* message_remove_header: function for removing any header from the message
* (except of unsupported yet Content- and MIME-Version special headers)
**/

static void
message_remove_header (GMimeMessage *message, const char *field)
{
        InternetAddress	*ia;
        GList		*list;
	gint		i;

	if (gmime_debug)
	  warn("message_remove_header(msg=0x%x, '%s')\n", message, field);

	for (i = 0; i < HEADER_UNKNOWN; ++i)
	  if (!g_strncasecmp(field, fields[i], strlen(fields[i])))
	    break;
	
	switch (i) {
	case HEADER_FROM:
	  if (message->from)
	    g_free (message->from);
	  message->from = NULL;
	  break;
	case HEADER_REPLY_TO:
	  if (message->reply_to)
	    g_free (message->reply_to);
	  message->reply_to = NULL;
	  break;
	case HEADER_TO: {
	  GList *recipients;
	  char *type = GMIME_RECIPIENT_TYPE_TO;

	  recipients = g_hash_table_lookup (message->recipients, type);
          g_hash_table_remove (message->recipients, type);
	  internal_recipients_destroy(recipients);
	  break;
	}
	case HEADER_CC: {
	  GList *recipients;
	  char *type = GMIME_RECIPIENT_TYPE_CC;
	  
	  recipients = g_hash_table_lookup (message->recipients, type);
          g_hash_table_remove (message->recipients, type);
	  internal_recipients_destroy(recipients);
	  break;
	}
	case HEADER_BCC: {
	  GList *recipients;
	  char *type = GMIME_RECIPIENT_TYPE_BCC;
	  
	  recipients = g_hash_table_lookup (message->recipients, type);
          g_hash_table_remove (message->recipients, type);
	  internal_recipients_destroy(recipients);
	  break;
	}
	case HEADER_SUBJECT:
	  if (message->subject)
	    g_free(message->subject);
	  message->subject = NULL;
	  break;
	case HEADER_DATE:
	  g_mime_message_set_header(message, field, NULL);
	  break;
	case HEADER_MESSAGE_ID:
	  if (message->message_id)
	    g_free (message->message_id);
	  message->message_id = NULL;
	  break;
	//default: /* HEADER_UNKNOWN */
	  //g_mime_header_remove(message->headers, field);
	  //g_mime_message_set_header(message, field, NULL);
	}

	/* remove header */
	local_header_remove(GMIME_OBJECT(message)->headers, field);
}

/* different declarations for different types of set and get functions */
typedef const char *(*GetFunc) (GMimeMessage *message);
typedef InternetAddressList *(*GetRcptFunc) (GMimeMessage *message, const char *type );
typedef GList *(*GetListFunc) (GMimeMessage *message, const char *type );
typedef void   (*SetFunc) (GMimeMessage *message, const char *value);
typedef void   (*SetListFunc) (GMimeMessage *message, const char *field, const char *value);

/** different types of functions
*
* FUNC_CHARPTR
*  - function with no arguments
*  - get returns char*
*
* FUNC_IA (from Internet Address)
*  - function with additional "field" argument from the fieldfunc table,
*  - get returns Glist*
*
* FUNC_LIST
*  - function with additional "field" argument (given arbitrary header field name)
*  - get returns Glist*
**/
enum {
	FUNC_CHARPTR = 0,
	FUNC_CHARFREEPTR,
	FUNC_IA,
	FUNC_LIST
};

/**
* fieldfunc struct: structure of MIME fields and corresponding get and set
* functions.
**/
static struct {
  char *	name;
  GetFunc	func;
  GetRcptFunc	rcptfunc;
  GetListFunc	getlistfunc;
  SetFunc	setfunc;
  SetListFunc	setlfunc;
  gint		functype;
} fieldfunc[] = {
  { "From",	g_mime_message_get_sender,	NULL, NULL,				g_mime_message_set_sender,	NULL, FUNC_CHARPTR },
  { "Reply-To",	g_mime_message_get_reply_to,	NULL, NULL,				g_mime_message_set_reply_to,	NULL, FUNC_CHARPTR },
  { "To",	NULL,				g_mime_message_get_recipients,	NULL, NULL, g_mime_message_add_recipients_from_string, FUNC_IA },
  { "Cc",	NULL,				g_mime_message_get_recipients,	NULL, NULL, g_mime_message_add_recipients_from_string, FUNC_IA },
  { "Bcc",	NULL,				g_mime_message_get_recipients,	NULL, NULL, g_mime_message_add_recipients_from_string, FUNC_IA },
  { "Subject",	g_mime_message_get_subject,	NULL, NULL,				g_mime_message_set_subject,	NULL, FUNC_CHARPTR },
  { "Date",	g_mime_message_get_date_string, NULL, NULL,				g_mime_message_set_date_from_string,	NULL, FUNC_CHARFREEPTR },
  { "Message-Id",g_mime_message_get_message_id,	NULL, NULL,				g_mime_message_set_message_id,	NULL, FUNC_CHARPTR },
  { NULL,	NULL,		NULL,	local_message_get_header,	NULL, g_mime_message_add_header, FUNC_LIST }
};

/**
* message_set_header: set header of any type excluding special (Content- and MIME-Version:)
**/
static void
message_set_header(GMimeMessage *message, const char *field, const char *value) {
  gint		i;

  if (gmime_debug)
    warn("message_set_header(msg=0x%x, '%s' => '%s')\n", message, field, value);

  if (!g_strcasecmp (field, "MIME-Version:") || !g_strncasecmp (field, "Content-", 8)) {
    warn ("Could not set special header yet: \"%s\"", field);
    return;
  }
  for (i=0; i<=HEADER_UNKNOWN; ++i) {
    if (!fieldfunc[i].name || !g_strncasecmp(field, fieldfunc[i].name, strlen(fieldfunc[i].name))) { 
      switch (fieldfunc[i].functype) {
	case FUNC_CHARPTR:
	  (*(fieldfunc[i].setfunc))(message, value);
	  break;
	case FUNC_IA:
          (*(fieldfunc[i].setlfunc))(message, fieldfunc[i].name, value);
	  break;
	case FUNC_LIST:
          (*(fieldfunc[i].setlfunc))(message, field, value);
	  break;
        default:
	  break;
      }
      break;
    }     
  }
}


/**
* message_get_header: returns the list of 'any header' values
* (except of unsupported yet Content- and MIME-Version special headers)
*
* You should free the GList list by yourself.
**/
static
GList *
message_get_header(GMimeMessage *message, const char *field) {
  gint		i;
  char *	ret = NULL;
  GList *	gret = NULL;

  for (i=0; i<=HEADER_UNKNOWN; ++i) {
    if (!fieldfunc[i].name || !g_strncasecmp(field, fieldfunc[i].name, strlen(fieldfunc[i].name))) { 
      if (gmime_debug)
        warn("message_get_header(%s) = %d",
	      field, fieldfunc[i].functype);
      switch (fieldfunc[i].functype) {
	case FUNC_CHARFREEPTR:
	  ret = (char *)(*(fieldfunc[i].func))(message);
	  break;
	case FUNC_CHARPTR:
	  ret = (char *)(*(fieldfunc[i].func))(message);
	  break;
	case FUNC_IA: {
	    GList *item, *gretcopy;
	    InternetAddressList *ia_list = NULL, *ia;
	    
	    warn("a m=0x%x f=%s\n", message, field);
            ia_list = (*(fieldfunc[i].rcptfunc))(message, field);
	    warn("a 0x%x\n", ia_list);
	    gret = g_list_alloc();
	    warn("b 0x%x\n", gret);
	    ia = ia_list;
	    // gret = item;
	    warn("cbefore 0x%x\n", gret);
	    while (ia && ia->address) {
	      char *ia_string;

	      ia_string = internet_address_to_string((InternetAddress *)ia->address, FALSE);
	      gret = g_list_append(gret, ia_string);
	      ia = ia->next;
	    }
	    warn("cout 0x%x\n", gret);
	  }
	  break;
	case FUNC_LIST:
          gret = (*(fieldfunc[i].getlistfunc))(message, field);
	  break;
        default:
	  break;
      }
      break;
    }     
  }
  if (gmime_debug)
    warn("message_get_header(%s) = 0x%x/%s ret=%s",
	    field, gret, gret ? (char *)(gret->data) : "", ret);
  if (gret == NULL && ret != NULL)
    gret = g_list_prepend(gret, g_strdup(ret));
  if (fieldfunc[i].functype == FUNC_CHARFREEPTR && ret)
    g_free(ret);
  return gret;
}

