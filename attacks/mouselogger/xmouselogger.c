#include <X11/X.h>
#include <X11/Xlib.h>
#include <X11/Xutil.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

static volatile sig_atomic_t run = 1;

static void sig_handler(int _) {
    (void)_;
    run = 0;
}

/**
 * Minimal example of a mouse logger
 */
int main() {
    signal(SIGINT, sig_handler);
    Display *d = XOpenDisplay(NULL);
    if (d == NULL) {
        fprintf(stderr, "Unable to open X display\n");
        return EXIT_FAILURE;
    }

    Window r, c;
    int rx = 0, ry = 0, x = 0, y = 0;
    unsigned int m;

    while (run) {
        XQueryPointer(d, DefaultRootWindow(d), &r, &c, &rx, &ry, &x, &y, &m);
        printf("At: %d, %d or %d, %d\n", rx, ry, x, y);
    }

    XCloseDisplay(d);
    return EXIT_SUCCESS;
}
