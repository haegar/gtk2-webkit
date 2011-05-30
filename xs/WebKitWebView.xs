#define LIBSOUP_USE_UNSTABLE_REQUEST_API

#include "perl_webkit.h"
#include <gperl_marshal.h>
#include <libsoup/soup.h>
#include <libsoup/soup-cache.h>

static SoupCache *soup_cache = NULL;

STATIC void
store_sting (gpointer key, gpointer value, gpointer user_data)
{
	if (!hv_store ((HV *)user_data, (const char *)key, strlen ((const char *)key),
	               newSVGChar ((const gchar *)value), 0)) {
		croak ("failed to store in hash");
	}
}

STATIC SV *
string_hashtable_to_hashref (GHashTable *params)
{
	HV *hv = newHV ();
	g_hash_table_foreach (params, store_sting, hv);
	return newRV_noinc ((SV *)hv);
}

STATIC void
perl_webkit_web_view_marshall_create_plugin_widget (GClosure *closure,
                                                    GValue *return_value,
                                                    guint n_param_values,
                                                    const GValue *param_values,
                                                    gpointer invocant_hint,
                                                    gpointer marshal_data)
{
	dGPERL_CLOSURE_MARSHAL_ARGS;

	PERL_UNUSED_VAR (return_value);
	PERL_UNUSED_VAR (n_param_values);
	PERL_UNUSED_VAR (invocant_hint);

	GPERL_CLOSURE_MARSHAL_INIT (closure, marshal_data);

	ENTER;
	SAVETMPS;
	PUSHMARK (SP);

	GPERL_CLOSURE_MARSHAL_PUSH_INSTANCE (param_values);

	XPUSHs (sv_2mortal (newSVGChar (g_value_get_string (param_values + 1))));
	XPUSHs (sv_2mortal (newSVGChar (g_value_get_string (param_values + 2))));
	XPUSHs (sv_2mortal (string_hashtable_to_hashref ((GHashTable *)g_value_get_boxed (param_values + 3))));

	GPERL_CLOSURE_MARSHAL_PUSH_DATA;

	PUTBACK;

	GPERL_CLOSURE_MARSHAL_CALL (G_SCALAR);

	SPAGAIN;

	if (count != 1) {
		croak ("create-plugin-widget handlers need to return a single value");
	}

	g_value_set_object (return_value, SvGtkWidget (POPs));

	FREETMPS;
	LEAVE;
}

STATIC bool
dirty_set_soup_feature(SoupSession *session, GType feature)
/* returns true if the feature has been added, false if it was already there */
{
	GSList *flist = soup_session_get_features (session, feature);
	guint feature_is_set = g_slist_length(flist);
	g_slist_free(flist);

	if (feature_is_set)
		return false;

	soup_session_add_feature_by_type(session, feature);
	return true;
}

STATIC void
dirty_soup_cache_finish(SoupSession *session)
{
	if (soup_cache) {
		soup_cache_flush(soup_cache);
		soup_cache_dump(soup_cache);
		g_object_unref(soup_cache);
		soup_cache = NULL;
	}
}

STATIC void
dirty_soup_cache_init(SoupSession *session, guint cache_size)
/* cache_size in mb */
{
	char *cache_dir;

	if (soup_cache) {
		dirty_soup_cache_finish(session);
	}

	cache_dir = g_build_filename(g_get_user_cache_dir (), g_get_prgname (), NULL);
	soup_cache = soup_cache_new(cache_dir, SOUP_CACHE_SINGLE_USER);
	g_free(cache_dir);

	if (!soup_cache)
		return;

	soup_session_add_feature(session, SOUP_SESSION_FEATURE(soup_cache));

	/* Cache size in Mb: 1024 * 1024 */
	soup_cache_set_max_size(soup_cache, cache_size << 20);

	soup_cache_load(soup_cache);

	SoupCache *dummy = (SoupCache *)soup_session_get_feature (session, SOUP_TYPE_CACHE);
	if (!dummy) {
		croak("FOOOOOOOOO");
	}
}


MODULE = Gtk2::WebKit::WebView	PACKAGE = Gtk2::WebKit::WebView	PREFIX = webkit_web_view_

PROTOTYPES: disable

BOOT:
	gperl_signal_set_marshaller_for (WEBKIT_TYPE_WEB_VIEW,
	                                 "create-plugin-widget",
	                                 perl_webkit_web_view_marshall_create_plugin_widget);

GtkWidget *
webkit_web_view_new (class)
	C_ARGS:

const gchar *
webkit_web_view_get_title (web_view)
		WebKitWebView *web_view

const gchar *
webkit_web_view_get_uri (web_view)
		WebKitWebView *web_view

void
webkit_web_view_set_maintains_back_forward_list (web_view, flag)
		WebKitWebView *web_view
		gboolean flag

WebKitWebBackForwardList *
webkit_web_view_get_back_forward_list (web_view)
		WebKitWebView *web_view

gboolean
webkit_web_view_go_to_back_forward_item (web_view, item)
		WebKitWebView *web_view
		WebKitWebHistoryItem *item

gboolean
webkit_web_view_can_go_back (web_view)
		WebKitWebView *web_view

gboolean
webkit_web_view_can_go_back_or_forward (web_view, steps)
		WebKitWebView *web_view
		gint steps

gboolean
webkit_web_view_can_go_forward (web_view)
		WebKitWebView *web_view

void
webkit_web_view_go_back (web_view)
		WebKitWebView *web_view

void
webkit_web_view_go_back_or_forward (web_view, steps)
		WebKitWebView *web_view
		gint steps

void
webkit_web_view_go_forward (web_view)
		WebKitWebView *web_view

void
webkit_web_view_stop_loading (web_view)
		WebKitWebView *web_view

void
webkit_web_view_open (web_view, uri)
		WebKitWebView *web_view
		const gchar *uri

void
webkit_web_view_reload (web_view)
		WebKitWebView *web_view

void
webkit_web_view_reload_bypass_cache (web_view)
		WebKitWebView *web_view

void
webkit_web_view_load_uri (web_view, uri)
		WebKitWebView *web_view
		const gchar *uri

void
webkit_web_view_load_string (web_view, content, content_mime_type, content_encoding, base_uri)
		WebKitWebView *web_view
		const gchar *content
		const gchar *content_mime_type
		const gchar *content_encoding
		const gchar *base_uri

void
webkit_web_view_load_html_string (web_view, content, base_uri)
		WebKitWebView *web_view
		const gchar *content
		const gchar *base_uri

void
webkit_web_view_load_request (web_view, request)
		WebKitWebView *web_view
		WebKitNetworkRequest *request

gboolean
webkit_web_view_search_text (web_view, string, case_sensitive, forward, wrap)
		WebKitWebView *web_view
		const gchar *string
		gboolean case_sensitive
		gboolean forward
		gboolean wrap

guint
webkit_web_view_mark_text_matches (web_view, string, case_sensitive, limit)
		WebKitWebView *web_view
		const gchar *string
		gboolean case_sensitive
		guint limit

void
webkit_web_view_set_highlight_text_matches (web_view, highlight)
		WebKitWebView *web_view
		gboolean highlight

void
webkit_web_view_unmark_text_matches (web_view)
		WebKitWebView *web_view

WebKitWebFrame *
webkit_web_view_get_main_frame (web_view)
		WebKitWebView *web_view

WebKitWebFrame *
webkit_web_view_get_focused_frame (web_view)
		WebKitWebView *web_view

void
webkit_web_view_execute_script (web_view, script)
		WebKitWebView *web_view
		const gchar *script

gboolean
webkit_web_view_can_cut_clipboard (web_view)
		WebKitWebView *web_view

gboolean
webkit_web_view_can_copy_clipboard (web_view)
		WebKitWebView *web_view

gboolean
webkit_web_view_can_paste_clipboard (web_view)
		WebKitWebView *web_view

void
webkit_web_view_cut_clipboard (web_view)
		WebKitWebView *web_view

void
webkit_web_view_copy_clipboard (web_view)
		WebKitWebView *web_view

void
webkit_web_view_paste_clipboard (web_view)
		WebKitWebView *web_view

void
webkit_web_view_delete_selection (web_view)
		WebKitWebView *web_view

gboolean
webkit_web_view_has_selection (web_view)
		WebKitWebView *web_view

void
webkit_web_view_select_all (web_view)
		WebKitWebView *web_view

gboolean
webkit_web_view_get_editable (web_view)
		WebKitWebView *web_view

void
webkit_web_view_set_editable (web_view, flag)
		WebKitWebView *web_view
		gboolean flag

GtkTargetList *
webkit_web_view_get_copy_target_list (web_view)
		WebKitWebView *web_view

GtkTargetList *
webkit_web_view_get_paste_target_list (web_view)
		WebKitWebView *web_view

void
webkit_web_view_set_settings (web_view, settings)
		WebKitWebView *web_view
		WebKitWebSettings *settings

WebKitWebSettings *
webkit_web_view_get_settings (web_view)
		WebKitWebView *web_view

WebKitWebInspector *
webkit_web_view_get_inspector (web_view)
		WebKitWebView *web_view

WebKitWebWindowFeatures *
webkit_web_view_get_window_features (web_view)
		WebKitWebView *web_view

gboolean
webkit_web_view_can_show_mime_type (web_view, mime_type)
		WebKitWebView *web_view
		const gchar *mime_type

gboolean
webkit_web_view_get_transparent (web_view)
		WebKitWebView *web_view

void
webkit_web_view_set_transparent (web_view, flag)
		WebKitWebView *web_view
		gboolean flag

gfloat
webkit_web_view_get_zoom_level (web_view)
		WebKitWebView *web_view

void
webkit_web_view_set_zoom_level (web_view, zoom_level)
		WebKitWebView *web_view
		gfloat zoom_level

void
webkit_web_view_zoom_in (web_view)
		WebKitWebView *web_view

void
webkit_web_view_zoom_out (web_view)
		WebKitWebView *web_view

gboolean
webkit_web_view_get_full_content_zoom (web_view)
		WebKitWebView *web_view

void
webkit_web_view_set_full_content_zoom (web_view, full_content_zoom)
		WebKitWebView *web_view
		gboolean full_content_zoom

#SoupSession *
#webkit_get_default_session (class)
#	C_ARGS:

const gchar *
webkit_web_view_get_encoding (web_view)
		WebKitWebView *web_view

void
webkit_web_view_set_custom_encoding (web_view, encoding)
		WebKitWebView *web_view
		const gchar *encoding

const gchar *
webkit_web_view_get_custom_encoding (web_view)
		WebKitWebView *web_view

void
webkit_web_view_move_cursor (web_view, step, count)
		WebKitWebView *web_view
		GtkMovementStep step
		gint count

WebKitLoadStatus
webkit_web_view_get_load_status (web_view)
		WebKitWebView *web_view

gdouble
webkit_web_view_get_progress (web_view)
		WebKitWebView *web_view

void
webkit_web_view_undo (web_view)
		WebKitWebView *web_view

gboolean
webkit_web_view_can_undo (web_view)
		WebKitWebView *web_view

void
webkit_web_view_redo (web_view)
		WebKitWebView *web_view

gboolean
webkit_web_view_can_redo (web_view)
		WebKitWebView *web_view

void
webkit_web_view_set_view_source_mode (web_view, view_source_mode)
		WebKitWebView *web_view
		gboolean view_source_mode

gboolean
webkit_web_view_get_view_source_mode (web_view)
		WebKitWebView *web_view

#WebKitHitTestResult *
#webkit_web_view_get_hit_test_result (web_view, event)
#		WebKitWebView *web_view
#		GdkEventButton *event

const gchar *
webkit_web_view_get_icon_uri (web_view)
		WebKitWebView *web_view

void
webkit_set_cache_model (class, cache_model)
		WebKitCacheModel cache_model
	C_ARGS:
		cache_model

WebKitCacheModel
webkit_get_cache_model (class)
	C_ARGS:

void
dirty_set_proxy (class, proxy_url)
# Set global proxy to use by all Gtk2::WebKit::WebView instances.
#
# Needs fully specified proxy url in the form http://username:pass@hostname:port,
# for example 'http://"":""@localhost:3128'
		char *proxy_url
	CODE:
		{
			SoupSession *session;
			SoupURI *soupUri;

			session = webkit_get_default_session();
			if (!session)
				return;

			if (proxy_url) {
				soupUri = soup_uri_new(proxy_url);
				g_object_set(session, SOUP_SESSION_PROXY_URI, soupUri, NULL);

				if (soupUri)
					soup_uri_free(soupUri);
			} else {
				soup_session_remove_feature_by_type(
					session,
					(GType) SOUP_SESSION_PROXY_URI);
			}
		}

void
dirty_clear_all_cookies (class)
	CODE:
		{
			SoupSession *session;
			SoupCookieJar *jar;
			GSList *all_cookies;
			GSList *cookie;

			session = webkit_get_default_session();
			if (!session)
				return;

			jar = SOUP_COOKIE_JAR(soup_session_get_feature(session, SOUP_TYPE_COOKIE_JAR));
			if (!jar)
				return;

			all_cookies = soup_cookie_jar_all_cookies(jar);
			if (!all_cookies)
				return;

			for (cookie = all_cookies; cookie; cookie = cookie->next)
				soup_cookie_jar_delete_cookie(jar, (SoupCookie*)cookie->data);

			soup_cookies_free(all_cookies);
		}

void
dirty_set_wanted_soup_features(class)
	CODE:
		{
			SoupSession *session;

			session = webkit_get_default_session();
			if (!session)
				return;

			dirty_set_soup_feature(session, (GType) WEBKIT_TYPE_SOUP_AUTH_DIALOG);
			dirty_soup_cache_init(session, 50);
		}

void
dirty_soup_cache_set_max_size(class, max_size)
	guint max_size
	CODE:
		{
			if (!soup_cache)
				return;

			soup_cache_set_max_size(soup_cache, max_size);
		}

guint
dirty_soup_cache_get_max_size(class)
	CODE:
		{
			RETVAL = 0;
			if (!soup_cache)
				return;

			RETVAL = soup_cache_get_max_size(soup_cache);
		}
	OUTPUT:
		RETVAL

void
dirty_soup_cache_flush(class)
	CODE:
		{
			if (!soup_cache)
				return;

			soup_cache_flush(soup_cache);
		}

void
dirty_soup_cache_clear(class)
	CODE:
		{
			if (!soup_cache)
				return;

			soup_cache_clear(soup_cache);
		}

void
dirty_soup_cache_dump(class)
	CODE:
		{
			if (!soup_cache)
				return;

			soup_cache_dump(soup_cache);
		}
