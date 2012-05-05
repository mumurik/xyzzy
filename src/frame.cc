#include "stdafx.h"
#include "ed.h"
#include "mainframe.h"


ApplicationFrame::ApplicationFrame ()
     : mouse (kbdq)
{
  auto_save_count = 0;
  ime_composition = 0;
  ime_open_mode = kbd_queue::IME_MODE_OFF;
  sleep_timer_exhausted = 0;
  last_vkeycode = -1;
  kbd_repeat_count = 0;
  wait_cursor_depth = 0;
  f_in_drop = 0;
  drop_window = 0;
  drag_window = 0;
  drag_buffer = 0;
  f_protect_quit = 0;
  hwnd_clipboard = 0;
  last_cmd_tick = GetTickCount ();
  f_auto_save_pending = 0;
  default_caret_blink_time = 0;
  last_blink_caret = 0;
  lquit_char = make_char ('G' - '@');
  quit_vkey = 'G';
  quit_mod = MOD_CONTROL;
  minibuffer_prompt_column = -1;
  mframe = new main_frame();
  lminibuffer_prompt = Qnil;
  lminibuffer_message = Qnil;

  memset((void*)&active_frame, 0, sizeof(active_frame));
  a_next = 0;
}

ApplicationFrame::~ApplicationFrame ()
{
	mframe->cleanup();
	delete mframe;
}


ApplicationFrame *root = NULL;

static void inline ensure_root()
{
	if(root == NULL)
	{
		root = new ApplicationFrame();
	}
}

ApplicationFrame& active_app_frame()
{
	ensure_root();
	return *root;
}

main_frame& active_main_frame()
{
	ensure_root();
	return *root->mframe;
}

ApplicationFrame *first_app_frame() { ensure_root(); return root; }


ApplicationFrame* retrieve_app_frame(HWND hwnd)
{
  return (ApplicationFrame *)GetWindowLong (hwnd, 0);
}

#include <vector>
static std::vector<ApplicationFrame*> g_floating_frames;
static std::vector<ApplicationFrame*> g_startup_second_pending_frames;


void app_frame_gc_mark(void (*f)(lisp))
{
  for(ApplicationFrame *app1 = root; app1; app1 = app1->a_next)
  {
	  Window *wp;
	  for (wp = app1->active_frame.windows; wp; wp = wp->w_next)
		(*f) (wp->lwp);
	  for (wp = app1->active_frame.reserved; wp; wp = wp->w_next)
		(*f) (wp->lwp);
	  for (wp = app1->active_frame.deleted; wp; wp = wp->w_next)
		(*f) (wp->lwp);

	  app1->mframe->gc_mark(f);

	  (*f)(app1->lminibuffer_message);
	  (*f)(app1->lminibuffer_prompt);
	  (*f)(app1->lquit_char);
	  (*f)(app1->lfp);
      app1->user_timer.gc_mark (f);
  }
}

// this needs all appframe, so implement in this file.
void
Window::modify_all_mode_line ()
{
  for(ApplicationFrame *app1 = root; app1; app1 = app1->a_next)
  {
	  for (Window *wp = app1->active_frame.windows; wp; wp = wp->w_next)
		wp->w_disp_flags |= WDF_MODELINE;
  }
}



void insert_app_frame(HWND hwnd, ApplicationFrame *app1)
{
  SetWindowLong (hwnd, 0, LONG (app1));
}

bool is_last_app_frame()
{
	if(root == NULL || root->a_next == NULL)
		return true;
	return false;
}

static void change_root_frame(ApplicationFrame *app1)
{
	if (root == app1) // do nothing.
		return;
	ApplicationFrame *cur = root;
	ApplicationFrame *prev = cur;
	while(cur != app1)
	{
		prev = cur;
		cur = cur->a_next;
	}
	assert(prev->a_next == app1);

	prev->a_next = app1->a_next;
	app1->a_next = root;
	root = app1;
}

void notify_focus(ApplicationFrame *app1)
{
	if (root == app1) // do nothing.
		return;

	/*
	most of the case, hs_focus turn off at KILL_FOCUS.
	But when inside read_minibuffer, defer_focus should update caret and other information even if they are inside eval call.
	So I apply re_focus in defer_focus_change, and that make has_focus non-zero in some case.
	*/
	root->active_frame.has_focus = 0;


	change_root_frame(app1);

	kbd_queue::change_application_window = true;
	for(Window* wp = root->active_frame.windows; wp; wp = wp->w_next)
		wp->update_window();
}

static void unchain_app_frame(ApplicationFrame* app1)
{
	if(root == app1){
		root = app1->a_next;
		app1->a_next = 0;
		return;
	}
	ApplicationFrame *app = root;
	while(app->a_next != app1)
	{
		app = app->a_next;
	}
	app->a_next = app1->a_next;
	app1->a_next = 0;
}


void delete_app_frame(ApplicationFrame *app1)
{
	unchain_app_frame(app1);
	// delete app1;
	g_floating_frames.push_back(app1);
	kbd_queue::change_application_window = true;
// 	notify_focus(root);
}

extern void remove_menus(ApplicationFrame* app);



void delete_floating_app_frame()
{
	for(std::vector<ApplicationFrame*>::iterator it = g_floating_frames.begin(); it != g_floating_frames.end(); it++)
	{
		ApplicationFrame *app1 = *it;
		remove_menus(app1);
		delete app1;
	}
	g_floating_frames.clear();
}

void call_all_startup_frame_second()
{
	for(std::vector<ApplicationFrame*>::iterator itr = g_startup_second_pending_frames.begin(); itr != g_startup_second_pending_frames.end(); itr++)
	{
		ApplicationFrame *app1 = *itr;
		change_root_frame(app1);
		if (xsymbol_function (Vstartup_frame_second) == Qunbound
			|| xsymbol_function (Vstartup_frame_second) == Qnil)
		return;

		suppress_gc sgc;
		try
		{
			funcall_1 (Vstartup_frame_second, app1->lfp);
		}
		catch (nonlocal_jump &)
		{
    		print_condition (nonlocal_jump::data());
		}
	}
	g_startup_second_pending_frames.clear();
}

extern int init_app(HINSTANCE hinst, ApplicationFrame* app1, ApplicationFrame* parent);

ApplicationFrame *
ApplicationFrame::coerce_to_frame (lisp object)
{
  if (!object || object == Qnil)
    return &active_app_frame ();
  check_appframe (object);
  if (!xappframe_fp (object))
    FEprogram_error (Edeleted_window);
  return xappframe_fp (object);
}


// --- below here is lisp functions.
lisp
Fmake_frame (lisp opt)
{
	ApplicationFrame *parent = root;
	HINSTANCE hinst = root->hinst;

	if (Qnil == selected_buffer(root)->run_hook_while_success (Vbefore_make_frame_hook))
		return Qnil;

    Window* window = selected_window (root);
    if (window)
      {
        window->save_buffer_params ();
      }

	ApplicationFrame* new_app = new ApplicationFrame();
	ApplicationFrame* next = root->a_next;
	root->a_next = new_app;
	new_app->a_next = next;
	g_startup_second_pending_frames.push_back(new_app);

	init_app(hinst, new_app, parent);

	defer_change_focus::request_change_focus(new_app);	
	return new_app->lfp;
}
lisp
Fselected_frame ()
{
  assert (xappframe_fp (active_app_frame ().lfp));
  assert (xappframe_fp (active_app_frame ().lfp) == &active_app_frame ());
  return active_app_frame ().lfp;
}

// ignore minibufp now.
lisp
Fnext_frame (lisp frame, lisp minibufp)
{
  ApplicationFrame *app = ApplicationFrame::coerce_to_frame(frame);
  ApplicationFrame *next = app->a_next;
  if (!next)
    next = first_app_frame();
  return next->lfp;
}

lisp
Fframe_list ()
{
  ApplicationFrame *app1 = first_app_frame();
  lisp result = xcons (app1->lfp, Qnil);
  lisp p = result;
  for(app1 = app1->a_next; app1; app1 = app1->a_next)
  {
      xcdr (p) = xcons (app1->lfp, Qnil);
      p = xcdr (p);
  }

  return result;
}

lisp
Fother_frame ()
{
  ApplicationFrame *app1 = first_app_frame();
  if(app1->a_next)
  {
	  SetFocus(app1->a_next->toplev);
	  return Qt;
  }
  return Qnil;
}

lisp
Fdelete_frame (lisp frame, lisp force)
{
  ApplicationFrame *app = ApplicationFrame::coerce_to_frame(frame);
  try
  {
	selected_buffer(app)->run_hook (Vdelete_frame_functions, app->lfp);
  }
  catch (nonlocal_jump &)
  {
    print_condition (nonlocal_jump::data ());
  }


  if(!is_last_app_frame())
  {
	  DestroyWindow (app->toplev);
	  return Qnil;
  }
  if(force != Qt)
	  return Qnil;
  Fkill_xyzzy();
  return Qnil;
}
