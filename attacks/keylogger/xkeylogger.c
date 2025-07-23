#include <X11/X.h>
#include <X11/Xlib.h>
#include <X11/Xutil.h>
#include <ctype.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static volatile sig_atomic_t run = 1;

static void sig_handler(int _) {
    (void)_;
    run = 0;
}

int main() {
    signal(SIGINT, sig_handler);
    Display *d;
    Window focus;
    int revert;
    char buf[16];
    int len;
    KeySym ks;
    XComposeStatus comp;
    static Window last_focus = None;

    d = XOpenDisplay(NULL);
    if (d == NULL) {
        fprintf(stderr, "Unable to open X display\n");
        return EXIT_FAILURE;
    }
    XGetInputFocus(d, &focus, &revert);
    XSelectInput(d, focus, KeyPressMask | KeyReleaseMask | FocusChangeMask);

    while (run) {
        if (XPending(d)) {
            XEvent ev;
            XNextEvent(d, &ev);
            switch (ev.type) {
            case FocusOut:
                if (focus != DefaultRootWindow(d)) {
                    XSelectInput(d, focus, 0);
                }
                if (XGetInputFocus(d, &focus, &revert) == BadWindow | focus == None) {
                    focus = DefaultRootWindow(d);
                }
                if (focus != last_focus) {
                    last_focus = focus;
                    printf("Focus changed to: %ld\n", focus);
                    if (focus != None && focus != PointerRoot) {
                        XSelectInput(d, focus, KeyPressMask | KeyReleaseMask | FocusChangeMask);
                    }
                }
                break;

            case KeyPress:
                len = XLookupString(&ev.xkey, buf, 16, &ks, &comp);
                if (len > 0 && isprint(buf[0])) {
                    buf[len] = 0;
                    printf("String is: %s\n", buf);
                } else {
                    printf("Key is: %d\n", (int)ks);
                }
            default:
                break;
            }
        } else {
            usleep(10000);
        }
    }

    XCloseDisplay(d);
    return EXIT_SUCCESS;
}
