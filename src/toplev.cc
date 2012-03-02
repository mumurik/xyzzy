#include "ed.h"
#include <imm.h>
#include <process.h>
#include "ctl3d.h"
#include "environ.h"
#include "fnkey.h"
#include "mainframe.h"
#include "reconv.h"
#include "wheel.h"

#define DnDTEST
#include "DnD.h"
#ifdef DnDTEST
text_drop_target tdropt;
#endif

mouse_wheel g_wheel;

static u_int __stdcall
quit_thread_entry (void *p)
{
  DWORD parent = (DWORD)p;

#define HK_BREAK 1
#define HK_QUIT 2

  RegisterHotKey (0, HK_BREAK, MOD_CONTROL, VK_CANCEL);
  SetTimer (0, 0, 1000, 0);

  int fg = 1;
  int quit_ok = 0;
  int quit_on = 0;

  HWND hwnd_fg;
  MSG msg;
  while (GetMessage (&msg, 0, 0, 0))
    {
	  ApplicationFrame *app1 = &active_app_frame();
      if (msg.hwnd)
        {
          XyzzyTranslateMessage (&msg);
          DispatchMessage (&msg);
        }
      else
        switch (msg.message)
          {
          case WM_TIMER:
            hwnd_fg = GetForegroundWindow ();
            msg.wParam = hwnd_fg ? GetWindowThreadProcessId (hwnd_fg, 0) == parent : 0;
			if(!msg.wParam)
			{
				// may be ghost window. 
				if(IsHungAppWindow(hwnd_fg))
				{
					if(IsHungAppWindow(app1->toplev))
					{
						msg.wParam = 1;
					}
				}
			}
            /* fall thru... */
          case WM_ACTIVATEAPP:
          case WM_PRIVATE_ACTIVATEAPP:
            if (msg.wParam)
              {
                if (!fg)
                  {
                    RegisterHotKey (0, HK_BREAK, MOD_CONTROL, VK_CANCEL);
                    fg = 1;
                  }
                if (!quit_on && quit_ok)
                  {
                    RegisterHotKey (0, HK_QUIT, app1->quit_mod, app1->quit_vkey);
                    quit_on = 1;
                  }
              }
            else
              {
                if (fg)
                  {
                    UnregisterHotKey (0, HK_BREAK);
                    fg = 0;
                  }
                if (quit_on)
                  {
                    UnregisterHotKey (0, HK_QUIT);
                    quit_on = 0;
                  }
              }
            break;

          case WM_PRIVATE_REGISTER_HOTKEY:
            quit_ok = 1;
            if (fg && !quit_on)
              {
                RegisterHotKey (0, HK_QUIT, app1->quit_mod, app1->quit_vkey);
                quit_on = 1;
              }
            break;

          case WM_PRIVATE_UNREGISTER_HOTKEY:
            quit_ok = 0;
            if (quit_on)
              {
                UnregisterHotKey (0, HK_QUIT);
                quit_on = 0;
              }
            break;

          case WM_PRIVATE_MODIFY_HOTKEY:
            if (quit_on)
              {
                UnregisterHotKey (0, HK_QUIT);
                RegisterHotKey (0, HK_QUIT, app1->quit_mod, app1->quit_vkey);
              }
            break;

          case WM_HOTKEY:
            if (!app1->f_protect_quit)
              {
                PostMessage (app1->toplev, WM_PRIVATE_QUIT, 0, 0);
                xsymbol_value (Vquit_flag) = Qt;
              }
            break;
          }
    }
  return 0;
}

int
start_quit_thread (ApplicationFrame* app1)
{
  u_long h = _beginthreadex (0, 0, quit_thread_entry, (void *)GetCurrentThreadId() ,
                             0, &g_app.quit_thread_id);
  if (h == -1)
    return 0;
  CloseHandle (HANDLE (h));
  return 1;
}

static void
set_current_cursor (const Window *wp)
{
  ApplicationFrame *app1 = wp != NULL ? wp->w_owner : first_app_frame();
  if (app1->wait_cursor_depth)
    SetCursor (sysdep.hcur_wait);
  else if (!wp || !wp->w_bufp)
    SetCursor (sysdep.hcur_arrow);
  else
    {
      POINT p;
      GetCursorPos (&p);
      ScreenToClient (wp->w_hwnd, &p);
      int l = wp->w_owner->text_font.cell ().cx / 2;
      if (wp->w_last_flags & Window::WF_LINE_NUMBER)
        l += (Window::LINENUM_COLUMNS + 1) * wp->w_owner->text_font.cell ().cx;
      SetCursor (p.x < l ? sysdep.hcur_revarrow : sysdep.hcur_current);
    }
}

static void
set_current_cursor (ApplicationFrame *app1)
{
  POINT p;
  GetCursorPos (&p);
  set_current_cursor (Window::find_scr_point_window (app1, p, 0, 0));
}

lisp
Fbegin_wait_cursor ()
{
  active_app_frame().wait_cursor_depth++;
  if (g_app.toplevel_is_active)
    {
      SetCursor (sysdep.hcur_wait);
      mouse_state::show_cursor ();
    }
  return Qt;
}

int
end_wait_cursor (int f, ApplicationFrame *app1)
{
  app1 = app1 == NULL ? &active_app_frame() : app1;
  if (!app1->wait_cursor_depth)
    return 1;
  if (f)
    app1->wait_cursor_depth = 0;
  else
    {
      app1->wait_cursor_depth--;
      if (app1->wait_cursor_depth)
        return 0;
    }
  if (g_app.toplevel_is_active)
    {
      if (GetFocus () == app1->toplev)
        mouse_state::hide_cursor ();
      set_current_cursor (app1);
    }
  return 1;
}

lisp
Fend_wait_cursor ()
{
  return boole (end_wait_cursor (0));
}

lisp
Fset_cursor (lisp cur)
{
  if (cur == Kibeam)
    sysdep.hcur_current = sysdep.hcur_ibeam;
  else if (cur == Karrow)
    sysdep.hcur_current = sysdep.hcur_arrow;
  else
    return Qnil;
  if (g_app.toplevel_is_active)
    set_current_cursor (&active_app_frame());
  xsymbol_value (Vcursor_shape) = cur;
  return Qt;
}

static void
frame_rect (ApplicationFrame *app1, int w, int h, RECT &r)
{
  GetClientRect (app1->hwnd_sw, &r);
  r.left = 0;
  r.top = 0;
  r.right = w;
  r.bottom = h - r.bottom;
  if (Window::w_default_flags & Window::WF_FUNCTION_BAR)
    r.bottom -= app1->active_frame.fnkey->height ();
}

static void
resize_toplevel (ApplicationFrame *app1, int cx, int cy)
{
  RECT r;
  frame_rect (app1, cx, cy, r);
  HWND hwnd_before;
  if (Window::w_default_flags & Window::WF_FUNCTION_BAR)
    {
      hwnd_before = app1->active_frame.fnkey->hwnd ();
      SetWindowPos (app1->active_frame.fnkey->hwnd (),
                    app1->hwnd_sw,
                    0, r.bottom,
                    cx, app1->active_frame.fnkey->height (),
                    SWP_DRAWFRAME | SWP_NOACTIVATE | SWP_SHOWWINDOW);
    }
  else
    {
      hwnd_before = app1->hwnd_sw;
      ShowWindow (app1->active_frame.fnkey->hwnd (), SW_HIDE);
    }

  app1->mframe->resize (r, hwnd_before);
}

void
recalc_toplevel (ApplicationFrame *app1)
{
  RECT r;
  GetClientRect (app1->toplev, &r);
  resize_toplevel (app1, r.right, r.bottom);
}

static void
do_dnd (HDROP hdrop)
{
  int drag_finish_called = 0;
  if (active_app_frame().kbdq.idlep ())
    {
      Window *wp;
      POINT pt;
      if (!DragQueryPoint (hdrop, &pt))
        wp = selected_window ();
      else
        {
          ClientToScreen (active_app_frame().toplev, &pt);
          wp = Window::find_scr_point_window (&active_app_frame(), pt, 1, 0);
        }

      if (wp)
        {
          if (wp->minibuffer_window_p () && !wp->w_bufp)
            wp = selected_window ();

          lisp hook = xsymbol_value (Vdrag_and_drop_hook);
          if (hook != Qunbound && hook != Qnil)
            {
              if (xsymbol_value (Vdrag_and_drop_auto_activate) != Qnil)
                {
                  if (IsIconic (active_app_frame().toplev))
                    ShowWindow (active_app_frame().toplev, SW_RESTORE);
                  ForceSetForegroundWindow (active_app_frame().toplev);
                }
              lisp list = Qnil;
              int nfiles = DragQueryFile (hdrop, UINT (-1), 0, 0);
              save_cursor_depth cursor_depth;
              try
                {
                  for (int i = 0; i < nfiles; i++)
                    {
                      char path[PATH_MAX];
                      DragQueryFile (hdrop, i, path, sizeof path);
                      list = xcons (make_string (path), list);
                    }
                  DragFinish (hdrop);
                  drag_finish_called = 1;
                  funcall_2 (hook, wp->lwp, list);
                }
              catch (nonlocal_jump &)
                {
                  print_condition (nonlocal_jump::data ());
                }
              refresh_screen (1);
            }
        }
    }
  if (!drag_finish_called)
    DragFinish (hdrop);
}

void
set_ime_caret (ApplicationFrame *app1)
{
  if (app1->active_frame.has_caret && app1->ime_composition)
    {
      HIMC hIMC = app1->kbdq.gime.ImmGetContext (app1->toplev);
      if (!hIMC)
        return;

      if (xsymbol_value (Vno_input_language_change_notification) != Qnil)
        app1->kbdq.init_kbd_encoding ();

      const FontObject &font = kbd_queue::kbd_encoding_font ();

      POINT pt (app1->active_frame.caret_pos);
      MapWindowPoints (app1->active_frame.has_caret, app1->toplev, &pt, 1);
      pt.x += font.offset ().x;
      pt.y += font.offset ().y;

      RECT r;
      int need_rect = (/*!app1->kbdq.gime.enable_p () // ようわからんけどとりあえず(^^;
                       ||*/ PRIMARYLANGID (app1->kbdq.kbd_langid ()) != LANG_KOREAN);
      if (need_rect)
        {
          GetClientRect (app1->active_frame.has_caret, &r);

		  Window *wp = app1->active_frame.windows;
          for (; wp; wp = wp->w_next)
            if (wp->w_hwnd == app1->active_frame.has_caret)
              break;
          r.left += app1->text_font.cell ().cx / 2;
          if (wp && wp->w_bufp)
            {
              if (wp->w_last_flags & Window::WF_LINE_NUMBER)
                r.left += (Window::LINENUM_COLUMNS + 1) * app1->text_font.cell ().cx;
              if (wp->get_fold_columns() != Buffer::FOLD_NONE)
                {
                  LONG t = r.left + wp->get_fold_columns() * app1->text_font.cell ().cx;
                  if (t > app1->active_frame.caret_pos.x)
                    r.right = min (r.right, t);
                }
            }
          MapWindowPoints (app1->active_frame.has_caret, app1->toplev,
                           (POINT *)&r, 2);
          pt.y = max (pt.y, r.top);
        }

      COMPOSITIONFORM cf;
      cf.dwStyle = CFS_POINT;
      cf.ptCurrentPos = pt;
      app1->kbdq.gime.ImmSetCompositionWindow (hIMC, &cf);

      if (need_rect)
        {
          cf.dwStyle = CFS_RECT;
          cf.rcArea = r;
          app1->kbdq.gime.ImmSetCompositionWindow (hIMC, &cf);
        }

      app1->kbdq.gime.ImmSetCompositionFont (hIMC, (LOGFONT *)&font.logfont ());
      app1->kbdq.gime.ImmReleaseContext (app1->toplev, hIMC);
    }
}

static void
ime_open_status (ApplicationFrame* app1, HWND hwnd)
{
  HIMC imc = app1->kbdq.gime.ImmGetContext (hwnd);
  if (imc)
    {
      app1->ime_open_mode = (app1->kbdq.gime.ImmGetOpenStatus (imc)
                           ? kbd_queue::IME_MODE_ON
                           : kbd_queue::IME_MODE_OFF);
      app1->kbdq.gime.ImmReleaseContext (hwnd, imc);
      Window::update_last_caret (app1);
      PostMessage (hwnd, WM_PRIVATE_IME_MODE, 0, 0);
    }
}

static LPARAM
ime_composition (ApplicationFrame *app1, HWND hwnd, LPARAM lparam)
{
  if (lparam & GCS_RESULTSTR)
    {
      HIMC hIMC = app1->kbdq.gime.ImmGetContext (hwnd);
      if (!hIMC)
        return lparam;

      if (xsymbol_value (Vno_input_language_change_notification) != Qnil)
        app1->kbdq.init_kbd_encoding ();

      if (xsymbol_value (Vunicode_ime) == Qnil
          ? !(app1->kbdq.ime_property () & IME_PROP_UNICODE)
          : xsymbol_value (Vunicode_ime) != Qt)
        {
          int l = app1->kbdq.gime.ImmGetCompositionString (hIMC, GCS_RESULTSTR, 0, 0);
          if (l > 0)
            {
              char *s = (char *)alloca (l + 1);
              if (app1->kbdq.gime.ImmGetCompositionString (hIMC, GCS_RESULTSTR, s, l) == l)
                {
                  app1->kbdq.puts (s, l);

                  lparam &= ~GCS_RESULTSTR;

                  int rl = app1->kbdq.gime.ImmGetCompositionString (hIMC, GCS_RESULTREADSTR, 0, 0);
                  if (rl > 0)
                    {
                      char *rs = (char *)alloca (rl + 1);
                      if (app1->kbdq.gime.ImmGetCompositionString (hIMC, GCS_RESULTREADSTR,
                                                                 rs, rl) == rl)
                        {
                          s[l] = rs[rl] = 0;
                          app1->ime_compq.push (s, l, rs, rl);
                        }
                    }
                }
            }
        }
      else
        {
          int l = app1->kbdq.gime.ImmGetCompositionStringW (hIMC, GCS_RESULTSTR, 0, 0);
          if (l > 0)
            {
              ucs2_t *s = (ucs2_t *)alloca (l + sizeof (ucs2_t));
              if (app1->kbdq.gime.ImmGetCompositionStringW (hIMC, GCS_RESULTSTR, s, l) == l)
                {
                  const Char *tab = 0;
                  switch (PRIMARYLANGID (app1->kbdq.kbd_langid ()))
                    {
                    case LANG_JAPANESE:
                      tab = wc2cp932_table;
                      break;

                    case LANG_KOREAN:
                      init_wc2ksc5601_table ();
                      tab = wc2ksc5601_table;
                      break;

                    case LANG_CHINESE:
                      switch (SUBLANGID (app1->kbdq.kbd_langid ()))
                        {
                        case SUBLANG_CHINESE_TRADITIONAL:
                        case SUBLANG_CHINESE_HONGKONG:
                          init_wc2big5_table ();
                          tab = wc2big5_table;
                          break;

                        case SUBLANG_CHINESE_SIMPLIFIED:
                        case SUBLANG_CHINESE_SINGAPORE:
                          init_wc2gb2312_table ();
                          tab = wc2gb2312_table;
                          break;
                        }
                      break;
                    }

                  l /= sizeof (ucs2_t);
                  for (ucs2_t *sp = s, *se = s + l; sp < se; sp++)
                    {
                      Char cc;
                      if ((!tab || (cc = tab[*sp]) == Char (-1))
                          && (cc = w2i (*sp)) == Char (-1))
                        {
                          app1->kbdq.putc (utf16_ucs2_to_undef_pair_high (*sp));
                          cc = utf16_ucs2_to_undef_pair_low (*sp);
                        }
                      app1->kbdq.putc (cc);
                    }
                  lparam &= ~GCS_RESULTSTR;

                  int rl = app1->kbdq.gime.ImmGetCompositionStringW (hIMC, GCS_RESULTREADSTR, 0, 0);
                  if (rl > 0)
                    {
                      ucs2_t *rs = (ucs2_t *)alloca (rl + sizeof (ucs2_t));
                      if (app1->kbdq.gime.ImmGetCompositionStringW (hIMC, GCS_RESULTREADSTR,
                                                                  rs, rl) == rl)
                        {
                          rl /= sizeof (ucs2_t);
                          s[l] = rs[rl] = 0;
                          app1->ime_compq.push (s, l, rs, rl, tab);
                        }
                    }
                }
            }
        }
      app1->kbdq.gime.ImmReleaseContext (hwnd, hIMC);
    }
  return lparam;
}

void
set_caret_blink_time (ApplicationFrame* app1)
{
  if (xsymbol_value (Vblink_caret) == Qnil)
    {
      if (!app1->default_caret_blink_time)
        app1->default_caret_blink_time = GetCaretBlinkTime ();
      if (app1->default_caret_blink_time)
        SetCaretBlinkTime (10000);
    }
}

void
restore_caret_blink_time (ApplicationFrame *app1)
{
  if (app1->default_caret_blink_time)
    {
      SetCaretBlinkTime (app1->default_caret_blink_time);
      app1->default_caret_blink_time = 0;
    }
}

static void
refresh_blink_interval (ApplicationFrame *app1)
{
  if (app1->ime_composition || GetFocus () != app1->toplev)
    return;
  if (xsymbol_value (Vblink_caret) == Qnil)
    {
      set_caret_blink_time (app1);
      if (app1->active_frame.has_caret)
        {
          Window *wp = selected_window (app1);
          if (wp)
            {
              wp->delete_caret (app1);
              wp->update_caret ();
            }
        }
    }
  else
    restore_caret_blink_time (app1);
}

extern void notify_focus(ApplicationFrame *app1);

static int
process_mouse_activate (ApplicationFrame *app1, LPARAM lparam)
{
  int r;
  if (g_app.toplevel_is_active
      || xsymbol_value (Veat_mouse_activate) == Qnil)
    r = MA_ACTIVATE;
  else
    switch (LOWORD (lparam))
      {
      case HTCLIENT:
      case HTHSCROLL:
      case HTVSCROLL:
        r = MA_ACTIVATEANDEAT;
        break;

      default:
        r = MA_ACTIVATE;
        break;
      }
  /*
  if (GetFocus () != app1->toplev)
    SetFocus (app1->toplev);
	*/

  return r;
}

static int
process_mouse_activate_client (ApplicationFrame *app1, LPARAM lparam)
{
  int r;
  if (g_app.toplevel_is_active
      || xsymbol_value (Veat_mouse_activate) == Qnil)
    r = MA_ACTIVATE;
  else
    switch (LOWORD (lparam))
      {
      case HTCLIENT:
      case HTHSCROLL:
      case HTVSCROLL:
        r = MA_ACTIVATEANDEAT;
        break;

      default:
        r = MA_ACTIVATE;
        break;
      }
  if (GetFocus () != app1->toplev)
    SetFocus (app1->toplev);

  return r;
}

LRESULT CALLBACK 
toplevel_wnd_create(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam)
{
  CREATESTRUCT *cs = (CREATESTRUCT *)lparam;
  ApplicationFrame *app1 = (ApplicationFrame *)cs->lpCreateParams;
  app1->toplev = hwnd;
  insert_app_frame(hwnd, app1);
  app1->hwnd_sw = CreateStatusWindow ((SBARS_SIZEGRIP | WS_CHILD | WS_VISIBLE
                                     | WS_CLIPCHILDREN | WS_CLIPSIBLINGS),
                                    0, hwnd, 0);
  if (!app1->hwnd_sw)
    return -1;

  app1->stat_area.init (app1->hwnd_sw);
  app1->status_window.set (app1->hwnd_sw);

  try
    {
      app1->active_frame.fnkey = new FKWin;
    }
  catch (nonlocal_jump &)
    {
      report_out_of_memory ();
      return -1;
    }
  if (!CreateWindow (FunctionKeyClassName, "",
                     (((Window::w_default_flags & Window::WF_FUNCTION_BAR)
                       ? WS_VISIBLE : 0)
                      | WS_CHILD | WS_CLIPSIBLINGS),
                     0, 0, 0, 0,
                     hwnd, 0, app1->hinst, app1->active_frame.fnkey))
    return -1;

  app1->active_frame.hwnd = CreateWindow (Application::FrameClassName, "",
                                        (WS_VISIBLE | WS_CHILD
                                         | WS_CLIPCHILDREN | WS_CLIPSIBLINGS),
                                        0, 0, 0, 0,
                                        hwnd, 0, app1->hinst, app1);
  if (!app1->active_frame.hwnd)
    return -1;

  app1->mframe->init(hwnd, app1->active_frame.hwnd);
  app1->user_timer.init (hwnd);

  DragAcceptFiles (hwnd, 1);
#ifdef DnDTEST
  RegisterDragDrop (hwnd, &tdropt);
#endif
  app1->hwnd_clipboard = SetClipboardViewer (hwnd);
  SetTimer (hwnd, TID_ITIMER, itimer::interval * 1000, 0);
  return 0;
}

extern ApplicationFrame *first_app_frame();
extern bool is_last_app_frame();
extern void delete_app_frame(ApplicationFrame *app1);

void change_focus_to_frame(ApplicationFrame *app1)
{
	  notify_focus(app1);
      app1->active_frame.has_focus = 1;
      app1->kbdq.toggle_ime (app1->ime_open_mode, 0);
      set_caret_blink_time (app1);
      Window::update_last_caret (app1);
      app1->active_frame.fnkey->update_vkey (0);
}

LRESULT CALLBACK
toplevel_wndproc (HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam)
{
  lChar cc;

  mouse_state::update_cursor (msg, wparam);
  if(msg == WM_CREATE) /* retrieve_app not yet available. */
      return toplevel_wnd_create(hwnd, msg, wparam, lparam);  

  ApplicationFrame *app1 = retrieve_app_frame(hwnd);
  if(app1 == NULL)
    app1 = first_app_frame();
  else if(app1 == (ApplicationFrame*)1)
	return DefWindowProc (hwnd, msg, wparam, lparam);
  switch (msg)
    {
    case WM_DESTROY:
	  if(is_last_app_frame())
	  {
		  end_listen_server ();
	#ifdef DnDTEST
		  RevokeDragDrop (hwnd);
	#endif
		  app1->user_timer.cleanup ();
		  environ::save_geometry ();
		  ChangeClipboardChain (hwnd, app1->hwnd_clipboard);
		  PostQuitMessage (0);
	  }
	  else
	  {
		  app1->user_timer.cleanup ();
		  ChangeClipboardChain (hwnd, app1->hwnd_clipboard);
	  }
	  app1->toplev = 0;
	  delete_app_frame(app1);
	  insert_app_frame(hwnd, (ApplicationFrame *)1);
      return 0;

    case WM_PAINT:
      {
        DWORD ostyle = GetWindowLong (hwnd, GWL_STYLE);
        SetWindowLong (hwnd, GWL_STYLE, ostyle | WS_CLIPCHILDREN);

        PAINTSTRUCT ps;
        HDC hdc = BeginPaint (hwnd, &ps);

        fill_rect (hdc, ps.rcPaint, sysdep.btn_face);

        RECT r;
        GetClientRect (hwnd, &r);
        draw_hline (hdc, 0, r.right, 0, sysdep.btn_shadow);

        GetWindowRect (app1->active_frame.hwnd, &r);
        MapWindowPoints (HWND_DESKTOP, hwnd, (POINT *)&r, 1);
        draw_hline (hdc, r.left, r.right, r.top - 1, sysdep.btn_shadow);

        EndPaint (hwnd, &ps);
        SetWindowLong (hwnd, GWL_STYLE, ostyle);
        return 0;
      }

    case WM_LBUTTONDOWN:
		app1->mframe->lbtn_down(lparam);
      return 0;

    case WM_PARENTNOTIFY:
      if (LOWORD (wparam) == WM_DESTROY)
        app1->mframe->child_destroy (HWND (lparam));
      break;

    case WM_NOTIFY:
      {
        LRESULT result = 0;
        if (app1->mframe->notify ((NMHDR *)lparam, result))
          return result;
        break;
      }

    case WM_CHANGECBCHAIN:
      if (HWND (wparam) == app1->hwnd_clipboard)
        app1->hwnd_clipboard = HWND (lparam);
      else if (app1->hwnd_clipboard)
        SendMessage (app1->hwnd_clipboard, msg, wparam, lparam);
      break;

    case WM_DRAWCLIPBOARD:
      if (app1->hwnd_clipboard)
        SendMessage (app1->hwnd_clipboard, msg, wparam, lparam);
      xsymbol_value (Vclipboard_newer_than_kill_ring_p) = Qt;
      xsymbol_value (Vkill_ring_newer_than_clipboard_p) = Qnil;
      break;

    case WM_SYSCOLORCHANGE:
      sysdep.load_colors ();
      Ctl3d::color_change ();
      Window::init_colors ();
      reload_caret_colors ();
      Window::update_last_caret (app1);
      SendMessage (app1->hwnd_sw, msg, wparam, lparam);
      break;

    case WM_INPUTLANGCHANGE:
      app1->kbdq.init_kbd_encoding (LANGID (lparam));
      ime_open_status (app1, hwnd);
      return 1;

    case WM_WININICHANGE:
    /*case WM_SETTINGCHANGE:*/
      Ctl3d::ini_change ();
      sysdep.load_settings ();
      app1->mframe->reload_settings ();
      {
        RECT or, nr;
        GetClientRect (app1->hwnd_sw, &or);
        SendMessage (app1->hwnd_sw, msg, wparam, lparam);
        GetClientRect (app1->hwnd_sw, &nr);
        app1->stat_area.reload_settings ();
        if (or.bottom != nr.bottom)
          {
            GetWindowRect (hwnd, &nr);
#if 1
            /* StatusWindow の Font が変更された場合に、クライアントエリアを
               それなりのサイズにしたいだけなんだけど、もっとまともな方法ある?
               って、NT でしか動いてないじゃん。*/
            WINDOWPOS wp;
            wp.hwnd = hwnd;
            wp.hwndInsertAfter = 0;
            wp.cx = nr.right - nr.left;
            wp.cy = nr.bottom - nr.top;
            wp.flags = SWP_NOACTIVATE | SWP_NOOWNERZORDER | SWP_NOZORDER;
            DefWindowProc (hwnd, WM_WINDOWPOSCHANGED, 0, LPARAM (&wp));
#else
            SetWindowPos (hwnd, 0, 0, 0, nr.right - nr.left, nr.bottom - nr.top,
                          SWP_NOACTIVATE | SWP_NOMOVE | SWP_NOZORDER | SWP_FRAMECHANGED);
#endif
          }
        else
          app1->stat_area.resize ();
      }
      if (!sysdep.Win4p ())
        {
          app1->kbdq.init_kbd_encoding ();
          ime_open_status (app1, hwnd);
        }
      return 0;

    case WM_ERASEBKGND:
      return 0;

    case WM_SIZE:
      SendMessage (app1->hwnd_sw, msg, wparam, lparam);
      app1->stat_area.resize ();
      if (wparam != SIZE_MINIMIZED)
        resize_toplevel (app1, LOWORD (lparam), HIWORD (lparam));
      return 0;

    case WM_MOVE:
      set_ime_caret (app1);
      break;

    case WM_SETFOCUS:
	  defer_change_focus::request_change_focus(app1);
      return 0;

    case WM_KILLFOCUS:
      app1->active_frame.has_focus = 0;
      restore_caret_blink_time (app1);
      Window::delete_caret (app1);
      app1->active_frame.fnkey->update_vkey (1);
      break;

    case WM_KEYUP:
    case WM_SYSKEYUP:
      app1->last_vkeycode = -1;
      app1->active_frame.fnkey->unset_vkey (wparam);
      break;

    case WM_SYSKEYDOWN:
#if 0
      if (xsymbol_value (Venable_meta_key) != Qnil
          || wparam == VK_F10)
#endif
        {
          app1->active_frame.fnkey->set_vkey (wparam);
          if (int (wparam) == app1->last_vkeycode)
            app1->kbd_repeat_count++;
          else
            {
              app1->last_vkeycode = wparam;
              app1->kbd_repeat_count = 1;
            }
          cc = decode_syskeys (wparam, lparam);
          if (cc != lChar_EOF)
            {
              app1->kbdq.putc (cc);
              return 0;
            }
        }
      break;

    case WM_MENUCHAR:
      if (HIWORD (wparam))
        return 0;
      app1->kbdq.putc (decode_syschars (LOWORD (wparam)));
      return 1;

    case WM_SYSCHAR:
      if (xsymbol_value (Venable_meta_key) != Qnil)
        {
          app1->kbdq.putc (decode_syschars (wparam));
          return 0;
        }
      break;

    case WM_KEYDOWN:
      app1->active_frame.fnkey->set_vkey (wparam);
      if (int (wparam) == app1->last_vkeycode)
        app1->kbd_repeat_count++;
      else
        {
          app1->last_vkeycode = wparam;
          app1->kbd_repeat_count = 1;
        }
      cc = decode_keys (wparam, lparam);
      if (cc != lChar_EOF)
        {
          app1->kbdq.putc (cc);
          return 0;
        }
      break;

    case WM_CHAR:
      if (xsymbol_value (Vno_input_language_change_notification) != Qnil)
        app1->kbdq.init_kbd_encoding ();
      app1->kbdq.putc (decode_chars (wparam));
      return 0;

    case WM_PRIVATE_WCHAR:
      {
        ucs2_t wc = ucs2_t (wparam);
        Char cc = w2i_half_width (wc);
        if (cc != Char (-1))
          app1->kbdq.putc (decode_chars (cc));
        else
          {
            app1->kbdq.putc (utf16_ucs2_to_undef_pair_high (wc));
            app1->kbdq.putc (utf16_ucs2_to_undef_pair_low (wc));
          }
        return 0;
      }

    case WM_IME_ENDCOMPOSITION:
      app1->ime_composition = 0;
      break;

    case WM_IME_STARTCOMPOSITION:
      app1->ime_composition = 1;
      set_ime_caret (app1);
      break;

    case WM_IME_NOTIFY:
      if (wparam == IMN_SETOPENSTATUS)
        ime_open_status (app1, hwnd);
      break;

    case WM_PRIVATE_IME_MODE:
      {
        selected_buffer (app1)->safe_run_hook (Vime_mode_hook, 0);
        for (Window *wp = app1->active_frame.windows; wp; wp = wp->w_next)
          if (wp->w_ime_mode_line)
            {
              wp->w_disp_flags |= Window::WDF_MODELINE;
              wp->redraw_mode_line ();
            }
        return 0;
      }

    case WM_IME_CHAR:
      if (xsymbol_value (Vno_input_language_change_notification) != Qnil)
        app1->kbdq.init_kbd_encoding ();
      app1->kbdq.putw (wparam);
      return 0;

    case WM_IME_COMPOSITION:
      lparam = ime_composition (app1, hwnd, lparam);
      break;

    case WM_PRIVATE_QUIT:
      {
        HWND active = get_active_window ();
        if (active == hwnd)
          app1->kbdq.putc (xchar_code (app1->lquit_char));
        else
          PostMessage (active, msg, wparam, lparam);
        return 0;
      }

    case WM_MOUSEACTIVATE:
      return process_mouse_activate (app1, lparam);

    case WM_PRIVATE_DELAYED_ACTIVATE:
      {
        save_cursor_depth cursor_depth;
        app1->kbdq.activate (wparam);
        return 0;
      }

    case WM_NCMOUSEMOVE:
      erase_popup (1, 1);
      break;

    case WM_ACTIVATE:
      {
        DWORD pid;
        GetWindowThreadProcessId (HWND (lparam), &pid);
        int eq = pid == GetCurrentProcessId ();
        if (LOWORD (wparam) != WA_INACTIVE)
          {
            app1->status_window.set (app1->hwnd_sw);
            if (!eq && !HIWORD (wparam))
              PostMessage (hwnd, WM_PRIVATE_DELAYED_ACTIVATE, 1, 0);
          }
        else
          {
            erase_popup (1, 0);
            if (!eq)
              PostMessage (hwnd, WM_PRIVATE_DELAYED_ACTIVATE, 0, 0);
          }
        break;
      }

    case WM_ACTIVATEAPP:
    case WM_PRIVATE_ACTIVATEAPP:
      g_app.toplevel_is_active = wparam;
      PostThreadMessage (g_app.quit_thread_id, msg, wparam, lparam);
      return 0;

    case WM_PRIVATE_PROCESS_OUTPUT:
      read_process_output (app1, wparam, lparam);
      return 0;

    case WM_PRIVATE_PROCESS_TERMINATE:
      wait_process_terminate (wparam, lparam);
      return 0;

    case WM_TIMER:
      switch (wparam)
        {
        case TID_USER:
          app1->user_timer.timer ();
          break;

        case TID_SLEEP:
          app1->sleep_timer_exhausted = 1;
          break;

        case TID_ITIMER:
          app1->stat_area.timer ();
          g_app.gc_itimer.inc ();
          app1->as_itimer.inc ();
          refresh_blink_interval (app1);
          if (app1->kbdq.idlep ())
            {
              if (g_app.gc_itimer.expired (30))
                {
                  g_app.gc_itimer.reset ();
                  if (ldataP::ld_nwasted)
                    app1->kbdq.gc_timer_expired ();
                }

              long interval;
              if (app1->f_auto_save_pending
                  || (app1->auto_save_count > 5
                      && safe_fixnum_value (xsymbol_value (Vauto_save_interval_timer),
                                            &interval)
                      && app1->as_itimer.expired (interval)))
                {
                  if (GetTickCount () - app1->last_cmd_tick < 5000)
                    app1->f_auto_save_pending = 1;
                  else
                    {
                      app1->as_itimer.reset ();
                      try
                        {
                          Fdo_auto_save (Qt);
                        }
                      catch (nonlocal_jump &)
                        {
                          print_condition (nonlocal_jump::data ());
                        }
                      app1->auto_save_count = 0;
                      app1->f_auto_save_pending = 0;
                    }
                  end_wait_cursor (1, app1);
                }
            }
          break;
        }
      return 0;

    case WM_QUERYENDSESSION:
      return Buffer::query_kill_xyzzy ();

    case WM_ENDSESSION:
      if (wparam)
        Buffer::kill_xyzzy (0);
      return 0;

    case WM_SYSCOMMAND:
      if ((wparam & 0xfff0) != SC_CLOSE)
        break;
      /* fall thru... */
    case WM_CLOSE:
	  if(is_last_app_frame())
	  {
        Buffer::kill_xyzzy (1);
        return 0;
	  }
	  break; /* call def proc */
    case WM_INITMENUPOPUP:
      if (!HIWORD (lparam))
        {
          init_menu_popup (app1, wparam, lparam);
          return 0;
        }
      break;

    case WM_COMMAND:
      if (!HIWORD (wparam))
        {
          app1->kbdq.putc (LCHAR_MENU | LOWORD (wparam));
          return 0;
        }
      break;

    case WM_PRIVATE_CALL_MENU:
      return DefWindowProc (hwnd, WM_SYSCHAR, wparam, lparam);

    case WM_DROPFILES:
      do_dnd (HDROP (wparam));
      return 0;

    case WM_SETCURSOR:
      if (app1->wait_cursor_depth)
        {
          SetCursor (sysdep.hcur_wait);
          return 1;
        }
      else if (app1->mframe->set_cursor (hwnd, wparam, lparam))
        return 1;
      break;

    case WM_ENTERMENULOOP:
      app1->f_protect_quit = 1;
      erase_popup (1, 0);
      break;

    case WM_EXITMENULOOP:
      app1->f_protect_quit = 0;
      break;
#if 1
    case WM_PRIVATE_FOREGROUND:
      Fsi_show_window_foreground ();
      return 1;
#endif

    case WM_NULL:
      break;

    case WM_IME_REQUEST:
      if (wparam == IMR_RECONVERTSTRING)
        return app1->kbdq.reconvert ((RECONVERTSTRING *)lparam, 0);
       if (wparam == IMR_DOCUMENTFEED)
        return app1->kbdq.documentfeed ((RECONVERTSTRING *)lparam, 0);
     break;

    case WM_DRAWITEM:
      if (app1->status_window.paint ((DRAWITEMSTRUCT *)lparam)
          || app1->mframe->draw_item ((DRAWITEMSTRUCT *)lparam))
        return 1;
      break;

    default:
      if (msg == wm_private_xyzzysrv)
        return read_listen_server (wparam, lparam);

      if (!sysdep.Win98p () && !sysdep.Win5p ())
        {
          static const UINT msime = RegisterWindowMessage (WM_MSIME_RECONVERT);
          static const UINT atok = RegisterWindowMessage (WM_ATOK_RECONVERT);
          if ((msg == msime || msg == atok)
              && wparam == IMR_RECONVERTSTRING)
            return app1->kbdq.reconvert ((RECONVERTSTRING *)lparam, 1);
          if (wparam == IMR_DOCUMENTFEED)
            return app1->kbdq.documentfeed ((RECONVERTSTRING *)lparam, 1);
         }

      wheel_info wi;
      if (xsymbol_value (Vsupport_mouse_wheel) != Qnil
          && g_wheel.msg_handler (hwnd, msg, wparam, lparam, wi))
        {
          Window *wp = Window::find_scr_point_window (app1, wi.wi_pt, 0, 0);
          if (wp)
            wp->wheel_scroll (wi);
          return 0;
        }
      break;
    }

  return app1->kbdq.gime.DefWindowProc (hwnd, msg, wparam, lparam);
}

static inline void
set_app_frame (HWND hwnd, ApplicationFrame *app1)
{
  SetWindowLong (hwnd, 0, LONG (app1));
}

static inline ApplicationFrame *
get_app_frame (HWND hwnd)
{
  return (ApplicationFrame *)GetWindowLong (hwnd, 0);
}


LRESULT CALLBACK
frame_wndproc (HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam)
{
  mouse_state::update_cursor (msg, wparam);
  switch (msg)
    {
    case WM_CREATE:
      {
        RECT r;
        CREATESTRUCT *cs = (CREATESTRUCT *)lparam;
		ApplicationFrame* app1 = (ApplicationFrame*)cs->lpCreateParams;
		set_app_frame(hwnd, app1);
        GetClientRect (app1->toplev, &r);
        frame_rect (app1, r.right, r.bottom, r);
        MoveWindow (hwnd, r.left, r.top, r.right - r.left, r.bottom - r.top, 0);
        return 0;
      }

    case WM_PAINT:
      {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint (hwnd, &ps);
        fill_rect (hdc, ps.rcPaint, sysdep.btn_face);
        for (Window *wp = get_app_frame(hwnd)->active_frame.windows; wp; wp = wp->w_next)
          if (wp->flags () & Window::WF_RULER)
            wp->paint_ruler (hdc);
        EndPaint (hwnd, &ps);
        return 0;
      }

    case WM_LBUTTONDOWN:
      return Window::frame_window_resize (get_app_frame(hwnd), hwnd, lparam);

    case WM_SIZE:
      if (get_app_frame(hwnd)->active_frame.windows)
        {
          SIZE osize = get_app_frame(hwnd)->active_frame.size;
          get_app_frame(hwnd)->active_frame.size.cx = LOWORD (lparam);
          get_app_frame(hwnd)->active_frame.size.cy = HIWORD (lparam);
          Window::compute_geometry (get_app_frame(hwnd), osize);
          Window::move_all_windows (get_app_frame(hwnd));
          Window::repaint_all_windows (get_app_frame(hwnd));
        }
      return 0;

    case WM_SETCURSOR:
      if (Window::frame_window_setcursor (get_app_frame(hwnd), hwnd, wparam, lparam))
        return 1;
      break;

    case WM_MOUSEACTIVATE:
      return process_mouse_activate (get_app_frame(hwnd), lparam);
    }

  return DefWindowProc (hwnd, msg, wparam, lparam);
}

static inline void
set_window (HWND hwnd, Window *wp)
{
  SetWindowLong (hwnd, 0, LONG (wp));
}

static inline Window *
get_window (HWND hwnd)
{
  return (Window *)GetWindowLong (hwnd, 0);
}




static int
on_vedge_p (ApplicationFrame *app1, HWND hwnd, POINT &p)
{
  ScreenToClient (hwnd, &p);
  if (p.x >= 0)
    return 0;

  RECT r;
  GetWindowRect (hwnd, &r);
  MapWindowPoints (HWND_DESKTOP, app1->active_frame.hwnd, (POINT *)&r, 2);
  return r.left;
}

static int
on_vedge_p (ApplicationFrame *app1, HWND hwnd)
{
  POINT p;
  GetCursorPos (&p);
  return on_vedge_p (app1, hwnd, p);
}

static inline ApplicationFrame*
get_app_frame_from_window(HWND hwnd)
{
  return get_window(hwnd)->w_owner;
}


LRESULT CALLBACK
client_wndproc (HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam)
{
  Window *wp;
  mouse_state::update_cursor (msg, wparam);
  switch (msg)
    {
    case WM_CREATE:
      {
        CREATESTRUCT *cs = (CREATESTRUCT *)lparam;
        wp = (Window *)cs->lpCreateParams;
        wp->w_hwnd = hwnd;
        set_window (hwnd, wp);
        return 0;
      }

    case WM_VSCROLL:
      if (GetFocus () != get_app_frame(hwnd)->toplev)
        SetFocus (get_app_frame(hwnd)->toplev);
      get_window (hwnd)->process_vscroll (LOWORD (wparam));
      return 0;

    case WM_HSCROLL:
      if (GetFocus () != get_app_frame(hwnd)->toplev)
        SetFocus (get_app_frame(hwnd)->toplev);
      get_window (hwnd)->process_hscroll (LOWORD (wparam));
      return 0;

    case WM_LBUTTONDOWN:
      get_app_frame_from_window(hwnd)->mouse.down (get_window (hwnd), wparam, lparam, MK_LBUTTON);
      return 0;

    case WM_MBUTTONDOWN:
      get_app_frame_from_window(hwnd)->mouse.down (get_window (hwnd), wparam, lparam, MK_MBUTTON);
      return 0;

    case WM_RBUTTONDOWN:
      get_app_frame_from_window(hwnd)->mouse.down (get_window (hwnd), wparam, lparam, MK_RBUTTON);
      return 0;

    case WM_XBUTTONDOWN:
      get_app_frame_from_window(hwnd)->mouse.down (get_window (hwnd), LOWORD (wparam), lparam,
                      (HIWORD (wparam) == XBUTTON1
                       ? MK_XBUTTON1 : MK_XBUTTON2));
      return 0;

    case WM_MOUSEMOVE:
      wp = get_window (hwnd);
      if (wparam & (MK_LBUTTON | MK_MBUTTON | MK_RBUTTON
                    | MK_XBUTTON1 | MK_XBUTTON2))
        set_current_cursor (wp);
      get_app_frame_from_window(hwnd)->mouse.move (wp, wparam, lparam);
      return 0;

    case WM_LBUTTONUP:
      get_app_frame_from_window(hwnd)->mouse.up (get_window (hwnd), wparam, lparam, MK_LBUTTON);
      return 0;

    case WM_MBUTTONUP:
      get_app_frame_from_window(hwnd)->mouse.up (get_window (hwnd), wparam, lparam, MK_MBUTTON);
      return 0;

    case WM_RBUTTONUP:
      get_app_frame_from_window(hwnd)->mouse.up (get_window (hwnd), wparam, lparam, MK_RBUTTON);
      return 0;

    case WM_XBUTTONUP:
      get_app_frame_from_window(hwnd)->mouse.up (get_window (hwnd), LOWORD (wparam), lparam,
                    HIWORD (wparam) == XBUTTON1 ? MK_XBUTTON1 : MK_XBUTTON2);
      return 0;

    case WM_CANCELMODE:
      get_app_frame_from_window(hwnd)->mouse.cancel ();
      break;

    case WM_ERASEBKGND:
      get_window (hwnd)->paint_background (HDC (wparam));
      return 1;

    case WM_PAINT:
      get_window (hwnd)->update_window ();
      return 0;

    case WM_SETCURSOR:
      switch (LOWORD (lparam))
        {
        case HTCLIENT:
          set_current_cursor (get_window (hwnd));
          return 1;

        case HTBORDER:
          if (on_vedge_p (get_app_frame_from_window(hwnd), hwnd) > 0)
            {
              SetCursor (sysdep.hcur_sizewe);
              return 1;
            }
          break;
        }
      break;

    case WM_NCLBUTTONDOWN:
      if (wparam == HTBORDER)
        {
          POINT point;
          point.x = short (LOWORD (lparam));
          point.y = short (HIWORD (lparam));
          int x = on_vedge_p (get_app_frame_from_window(hwnd), hwnd, point);
          if (x > 0)
            {
              point.x = short (LOWORD (lparam));
              point.y = short (HIWORD (lparam));
              ScreenToClient (get_app_frame_from_window(hwnd)->active_frame.hwnd, &point);
              Window::frame_window_resize (get_app_frame_from_window(hwnd), get_app_frame_from_window(hwnd)->active_frame.hwnd,
                                           MAKELONG (x - 1, point.y),
                                           &point);
              return 0;
            }
        }
      break;

    case WM_SIZE:
      if (wparam != SIZE_MINIMIZED)
        {
          wp = get_window (hwnd);
          if (wp)
            {
              wp->calc_client_size (LOWORD (lparam) - Window::RIGHT_PADDING,
                                    HIWORD (lparam));
              wp->winsize_changed (LOWORD (lparam), HIWORD (lparam));
            }
        }
      break;

    case WM_PASTE:
      get_app_frame_from_window(hwnd)->kbdq.paste ();
      break;

    case WM_NCMOUSEMOVE:
      erase_popup (1, 1);
      break;

    case WM_MOUSEACTIVATE:
      return process_mouse_activate_client (get_app_frame_from_window(hwnd), lparam);

    case WM_SETFOCUS:
      SetFocus (get_app_frame_from_window(hwnd)->toplev);
      return 0;
    }

  return DefWindowProc (hwnd, msg, wparam, lparam);
}

LRESULT CALLBACK
modeline_wndproc (HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam)
{
  Window *wp;
  switch (msg)
    {
    case WM_CREATE:
      {
        CREATESTRUCT *cs = (CREATESTRUCT *)lparam;
        wp = (Window *)cs->lpCreateParams;
        wp->w_hwnd_ml = hwnd;
        set_window (hwnd, wp);
        return 0;
      }

    case WM_LBUTTONDOWN:
      {
        POINT point;
        point.x = short (LOWORD (lparam));
        point.y = short (HIWORD (lparam));
        Window *wp = get_window (hwnd);
        if (!wp)
          return 0;
        MapWindowPoints (hwnd, get_app_frame_from_window(hwnd)->active_frame.hwnd, &point, 1);
        return wp->frame_window_resize (get_app_frame_from_window(hwnd)->active_frame.hwnd, point, 0);
      }

    case WM_PAINT:
      get_window (hwnd)->paint_mode_line ();
      return 0;

    case WM_MOUSEMOVE:
    case WM_NCMOUSEMOVE:
      erase_popup (1, 1);
      break;
    }

  return DefWindowProc (hwnd, msg, wparam, lparam);
}

class keyvec
{
  lisp v_buf[64];
  long v_length;
  long v_size;
  lisp *v_vec;
  int v_finished;
public:
  keyvec () : v_length (0), v_size (numberof (v_buf)), v_vec (v_buf), v_finished (1) {}
  ~keyvec () {if (v_vec != v_buf) free (v_vec);}
  void init ();
  void finish () {v_finished = 1;}
  int finished_p () const {return v_finished;}
  lisp lookup (Char c) {return lookup_keymap (c, v_vec, v_length);}
  void translate (lisp, lisp);
  void gc_mark_object (void (*)(lisp));
};

void
keyvec::init ()
{
  Buffer *bp = selected_buffer ();
  long l, n;

  if (safe_fixnum_value (Flist_length (bp->lminor_map), &l))
    {
      n = l + 3;
      if (n > v_size)
        {
          long size = (n + 63) & ~63;
          lisp *x = (lisp *)malloc (sizeof *x * size);
          if (x)
            {
              if (v_vec != v_buf)
                free (v_vec);
              v_vec = x;
              v_size = size;
            }
        }
      n = min (n, v_size) - 2;
      l = 0;
      v_vec[l++] = Fcurrent_selection_keymap ();
      for (lisp p = bp->lminor_map; consp (p) && l < n; l++, p = xcdr (p))
        v_vec[l] = xcar (p);
    }
  else
    {
      l = 0;
      v_vec[l++] = Fcurrent_selection_keymap ();
    }

  v_vec[l++] = bp->lmap;
  v_vec[l++] = xsymbol_value (Vglobal_keymap);
  v_length = l;
  v_finished = 0;
}

void
keyvec::translate (lisp old_command, lisp new_command)
{
  for (long i = 0; i < v_length; i++)
    if (v_vec[i] == old_command)
      v_vec[i] = new_command;
}

void
keyvec::gc_mark_object (void (*fn)(lisp))
{
  for (long i = 0; i < v_length; i++)
    (*fn)(v_vec[i]);
}

static keyvec g_map;

void
toplev_gc_mark (void (*fn)(lisp))
{
  g_map.gc_mark_object (fn);
}

int
toplev_accept_mouse_move_p ()
{
  return g_map.finished_p ();
}

static lisp
dispatch (lChar cc, ApplicationFrame *app1)
{
  lisp command;
  Char c = Char (cc);

  g_app.gc_itimer.reset ();
  app1->as_itimer.reset ();
  app1->last_cmd_tick = GetTickCount ();

  if (cc & LCHAR_MENU)
    {
      if (c >= MENU_ID_RANGE_MIN && c < MENU_ID_RANGE_MAX)
        command = lookup_menu_command (app1, c);
      else if (c >= TOOL_ID_RANGE_MIN && c < TOOL_ID_RANGE_MAX)
        command = app1->mframe->lookup_command (c);
      else
        return Qt;
      if (command == Qnil)
        return Qt;
    }
  else
    {
      if (g_map.finished_p ())
        {
          xsymbol_value (Vprefix_args) = xsymbol_value (Vnext_prefix_args);
          xsymbol_value (Vnext_prefix_args) = Qnil;
          xsymbol_value (Vprefix_value) = xsymbol_value (Vnext_prefix_value);
          xsymbol_value (Vnext_prefix_value) = Qnil;

          if (!meta_char_p (c) && !meta_function_char_p (c)
              && !function_char_p (c)
              && (DBCP (c) || (SBCP (c) && !ascii_char_p (c))))
            {
              command = symbol_value (Vdefault_input_function, selected_buffer (app1));
              if (command == Qnil || command == Qunbound)
                return Qt;
              goto run_command;
            }
          g_map.init ();
        }
      else if (char_mouse_move_p (c))
        return Qt;

      command = g_map.lookup (c);
      if (!command)
        {
          app1->keyseq.push (c, !app1->kbdq.macro_is_running ());
          Fcontinue_pre_selection ();
          app1->kbdq.close_ime ();
          return Qt;
        }
    }

run_command:
  xsymbol_value (Vlast_command) = xsymbol_value (Vthis_command);
  xsymbol_value (Vthis_command) = command;
  xsymbol_value (Vlast_command_char) = make_char (Char (c));
  if (command != Qnil)
    {
      selected_buffer (app1)->safe_run_hook (Vpre_command_hook, 1);
      if (xsymbol_value (Vthis_command) != command)
        {
          lisp new_command = xsymbol_value (Vthis_command);
          if (Fkeymapp (new_command) != Qnil)
            {
              xsymbol_value (Vthis_command) = xsymbol_value (Vlast_command);
              g_map.translate (command, new_command);
              app1->keyseq.push (c, !app1->kbdq.macro_is_running ());
              Fcontinue_pre_selection ();
              app1->kbdq.close_ime ();
              return Qt;
            }
          command = new_command;
        }
    }

  g_map.finish ();

  if (!app1->kbdq.macro_is_running ())
    app1->status_window.clear ();
  app1->keyseq.done (c, !app1->kbdq.macro_is_running ());
  app1->kbdq.restore_ime ();
  app1->kbdq.set_next_command_key ();

  selected_buffer (app1)->b_ime_mode = app1->ime_open_mode;

  if (command == Qnil)
    {
      if (!char_mouse_move_p (CCF_MOUSEMOVE))
        {
          app1->status_window.puts (Ekey_not_bound, 1);
          if (xsymbol_value (Vbeep_on_warn) != Qnil)
            Fding ();
        }
      app1->kbdq.clear ();
      app1->kbdq.end_last_command_key ();
      return Qnil;
    }

  lisp result = Qnil;
  try
    {
      stack_trace trace (stack_trace::apply, Scommand_execute, command, 0);
      result = Fcommand_execute (command, 0);
    }
  catch (nonlocal_jump &)
    {
      nonlocal_data *nld = nonlocal_jump::data ();
      if (nld->type == Qexit_this_level)
        throw;
      print_condition (nonlocal_jump::data ());
      app1->kbdq.clear ();
    }
  protect_gc gcpro (result);
  selected_buffer (app1)->safe_run_hook (Vpost_command_hook, 1);
  app1->kbdq.end_last_command_key ();
  erase_popup (0, 0);
  end_wait_cursor (1);
  WINFS::clear_share_cache ();
  return result;
}

#include <exception>

extern void delete_floating_app_frame();

void
main_loop ()
{
  dynamic_bind dynb0 (Vsi_condition_handlers, Qnil);
  dynamic_bind dynb1 (Vprefix_value, Qnil);
  dynamic_bind dynb2 (Vprefix_args, Qnil);
  dynamic_bind dynb3 (Vnext_prefix_value, Qnil);
  dynamic_bind dynb4 (Vnext_prefix_args, Qnil);
  dynamic_bind dynb5 (Vthis_command, Qnil);
  dynamic_bind dynb6 (Vlast_command, Qnil);

  save_command_key_index sck (active_app_frame().kbdq);
  while (1)
    {
      if (active_app_frame().kbdq.macro_is_running ())
        pending_refresh_screen ();
      else
        {
          if (stringp (active_app_frame().lminibuffer_message))
            {
              active_app_frame().lminibuffer_message = Qnil;
              Window::minibuffer_window ()->w_disp_flags |= Window::WDF_WINDOW;
            }
          refresh_screen (1);
        }
      xsymbol_value (Vquit_flag) = Qnil;
      xsymbol_value (Vinhibit_quit) = Qnil;
      xsymbol_value (Vsi_find_motion) = Qt;
      xsymbol_value (Vevalhook) = Qnil;
      xsymbol_value (Vapplyhook) = Qnil;
      active_app_frame().mouse.clear_move ();
	  lChar c;
	  try
	  {
		  c = active_app_frame().kbdq.fetch (1, toplev_accept_mouse_move_p ());
	  }
	  catch(std::exception)
	  {
		  delete_floating_app_frame();
		  continue;
	  }
      if (c == lChar_EOF)
        break;

      while (1)
        {
		  ApplicationFrame *app1 = &active_app_frame();
          dispatch (c, app1);
		  try
		  {
	          c = app1->kbdq.peek (toplev_accept_mouse_move_p ());
		  }
		  catch(std::exception)
		  {
			  delete_floating_app_frame();
	          c = active_app_frame().kbdq.peek (toplev_accept_mouse_move_p ());
			  continue;
		  }
          if (c == lChar_EOF)
            break;
          pending_refresh_screen ();
		  // I think this line should be active_app_frame() instead of app1.
          if (!active_app_frame().kbdq.macro_is_running ())
            Fundo_boundary ();
        }

      if (!active_app_frame().f_auto_save_pending
          && !active_app_frame().kbdq.macro_is_running ())
        {
          active_app_frame().auto_save_count++;
          long interval;
          if (safe_fixnum_value (xsymbol_value (Vauto_save_interval),
                                 &interval)
              && interval > 0 && active_app_frame().auto_save_count >= interval)
            active_app_frame().f_auto_save_pending = 1;
        }
    }
}

lisp
execute_string (lisp string)
{
  check_stack_overflow ();
  save_command_key_index sck (active_app_frame().kbdq);
  check_string (string);
  if (active_app_frame().kbdq.lookup_kbd_macro (string))
    FEsimple_error (Ekbd_macro_called_recursively);
  lisp val = xsymbol_value (Vprefix_value);
  int n = val == Qnil ? 1 : fixnum_value (val);
  lisp result = Qt;
  if (xstring_length (string))
    for (int i = 0; !n || i < n; i++)
      {
        kbd_macro_context macro (active_app_frame().kbdq, string);
        while (macro.running ())
          {
            xsymbol_value (Vquit_flag) = Qnil;
            xsymbol_value (Vinhibit_quit) = Qnil;
            lChar c = active_app_frame().kbdq.fetch (0, 0);
            if (c == lChar_EOF)
              return result;
            result = dispatch (c, &active_app_frame());
            if (result == Qnil)
              return result;
            pending_refresh_screen ();
            QUIT;
          }
        QUIT;
      }
  return result;
}

lisp
Fsi_minibuffer_message (lisp message, lisp prompt)
{
  active_app_frame().minibuffer_prompt_column = -1;
  if (message == Qnil)
    active_app_frame().lminibuffer_message = Qnil;
  else
    {
      check_string (message);
      active_app_frame().lminibuffer_message = message;
      active_app_frame().lminibuffer_prompt = boole (prompt && prompt != Qnil);
    }
  Window::minibuffer_window ()->w_disp_flags |= Window::WDF_WINDOW;
  if (!active_app_frame().kbdq.macro_is_running ())
    refresh_screen (0);
  return Qt;
}

lisp
Fcancel_mouse_event ()
{
  active_app_frame().mouse.cancel ();
  return Qt;
}

int
wait_process_terminate (HANDLE h)
{
  active_app_frame().kbdq.wait_event (h);
  return 1;
}

lisp
Fmain_loop ()
{
  check_kbd_enable ();
  int abnormal_exit = 0;
  try
    {
      main_loop ();
      abnormal_exit = 1;
    }
  catch (nonlocal_jump &)
    {
    }

  if (abnormal_exit)
    Fexit_recursive_edit (Qnil);

  lisp r = nonlocal_jump::data ()->value;
  return r ? r : Qnil;
}

lisp
Fsi_show_window_foreground ()
{
  if (IsIconic (active_app_frame().toplev))
    ShowWindow (active_app_frame().toplev, SW_RESTORE);
  ForceSetForegroundWindow (get_active_window ());
  return Qnil;
}

lisp
Fsi_activate_toplevel ()
{
  if (IsWindowEnabled (active_app_frame().toplev))
    {
      if (IsIconic (active_app_frame().toplev))
        ShowWindow (active_app_frame().toplev, SW_RESTORE);
      SetActiveWindow (active_app_frame().toplev);
      return Qt;
    }
  return Qnil;
}

lisp
Fcall_menu (lisp ln)
{
  int req = fixnum_value (ln);
  HMENU hmenu = GetMenu (active_app_frame().toplev);
  if (!hmenu)
    return Qnil;
  int n = GetMenuItemCount (hmenu);
  if (req < 0 || req >= n)
    return Qnil;
  char buf[1024], *b = buf;
  if (!GetMenuString (hmenu, req, buf, sizeof buf, MF_BYPOSITION))
    return Qnil;
  while (1)
    {
      b = jindex (b, '&');
      if (!b || !b[1])
        return Qnil;
      if (b[1] == '&')
        b += 2;
      else
        break;
    }
  PostMessage (active_app_frame().toplev, WM_PRIVATE_CALL_MENU, b[1], (1 << 29) | 1);
  return Qt;
}

lisp
Fset_quit_char (lisp ch)
{
  check_char (ch);

  Char cc = xchar_code (ch);
  int vk = -1, mod = 0;
  if (meta_char_p (cc))
    {
      mod |= MOD_ALT;
      cc = meta_char_to_char (cc);
    }
  else if (meta_function_char_p (cc))
    {
      mod |= MOD_ALT;
      cc = meta_function_to_function (cc);
    }

  if (function_char_p (cc))
    {
      if (pseudo_ctlchar_p (cc))
        {
          mod |= MOD_CONTROL;
          cc = pseudo_ctl2char_table[cc & 0xff];
        }
      else
        {
          if (cc & CCF_SHIFT_BIT)
            mod |= MOD_SHIFT;
          if (cc & CCF_CTRL_BIT)
            mod |= MOD_CONTROL;
          cc &= ~(CCF_SHIFT_BIT | CCF_CTRL_BIT);
          if (cc == CCF_APPS)
            vk = VK_APPS;
          else if (cc >= CCF_PRIOR && cc <= CCF_HELP)
            vk = VK_PRIOR + cc - CCF_PRIOR;
          else
            vk = VK_F1 + cc - CCF_F1;
        }
    }
  else
    {
      if (!ascii_char_p (cc))
        return Qnil;

      if (cc < ' ')
        {
          mod |= MOD_CONTROL;
          cc += '@';
        }
      else if (cc == CC_DEL)
        {
          mod |= MOD_CONTROL;
          cc = '?';
        }

      if (alpha_char_p (cc))
        vk = _char_upcase (cc);
    }

  if (vk < 0)
    {
      vk = VkKeyScan (CHAR (cc));
      if (LOWORD (vk) == -1)
        return Qnil;
      if (HIBYTE (vk) & 1)
        mod |= MOD_SHIFT;
      vk = LOBYTE (vk);
    }

  active_app_frame().lquit_char = ch;
  active_app_frame().quit_vkey = vk;
  active_app_frame().quit_mod = mod;

  PostThreadMessage (g_app.quit_thread_id, WM_PRIVATE_MODIFY_HOTKEY, 0, 0);

  return ch;
}

lisp
Fquit_char ()
{
  return active_app_frame().lquit_char;
}
