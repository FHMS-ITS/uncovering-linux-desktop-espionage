#include <X11/Xlib.h>
#include <X11/extensions/XInput2.h>
#include <stdio.h>
#include <string.h>

// Source: https://keithp.com/blogs/Cursor_tracking/

static int has_xi2(Display *dpy) {
    int major, minor;
    int rc;

    major = 2;
    minor = 2;

    rc = XIQueryVersion(dpy, &major, &minor);
    if (rc == BadRequest) {
        printf("No XI2 support. Server supports version %d.%d only.\n", major,
               minor);
        return 0;
    } else if (rc != Success) {
        fprintf(stderr, "Internal Error! This is a bug in Xlib.\n");
    }

    printf("XI2 supported. Server provides version %d.%d.\n", major, minor);

    return 1;
}

static void select_events(Display *dpy, Window win) {
    XIEventMask evmasks[1];
    unsigned char mask1[(XI_LASTEVENT + 7) / 8];

    memset(mask1, 0, sizeof(mask1));

    /* select for button and key events from all master devices */
    XISetMask(mask1, XI_RawMotion);

    evmasks[0].deviceid = XIAllMasterDevices;
    evmasks[0].mask_len = sizeof(mask1);
    evmasks[0].mask = mask1;

    XISelectEvents(dpy, win, evmasks, 1);
    XFlush(dpy);
}

int main(int argc, char **argv) {
    Display *dpy;
    int xi_opcode, event, error;
    XEvent ev;

    dpy = XOpenDisplay(NULL);

    if (!dpy) {
        fprintf(stderr, "Failed to open display.\n");
        return -1;
    }

    if (!XQueryExtension(dpy, "XInputExtension", &xi_opcode, &event, &error)) {
        printf("X Input extension not available.\n");
        return -1;
    }

    if (!has_xi2(dpy))
        return -1;

    /* select for XI2 events */
    select_events(dpy, DefaultRootWindow(dpy));

    while (1) {
        XGenericEventCookie *cookie = &ev.xcookie;
        XIRawEvent *re;
        Window root_ret, child_ret;
        int root_x, root_y;
        int win_x, win_y;
        unsigned int mask;

        XNextEvent(dpy, &ev);

        if (cookie->type != GenericEvent || cookie->extension != xi_opcode ||
            !XGetEventData(dpy, cookie))
            continue;

        switch (cookie->evtype) {
        case XI_RawMotion:
            re = (XIRawEvent *)cookie->data;
            XQueryPointer(dpy, DefaultRootWindow(dpy), &root_ret, &child_ret,
                          &root_x, &root_y, &win_x, &win_y, &mask);
            printf("raw %g,%g root %d,%d\n", re->raw_values[0],
                   re->raw_values[1], root_x, root_y);
            break;
        }
        XFreeEventData(dpy, cookie);
    }

    return 0;
}
