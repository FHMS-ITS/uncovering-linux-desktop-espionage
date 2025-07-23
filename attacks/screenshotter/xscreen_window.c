#include <stdio.h>
#include <stdlib.h>

#include <X11/X.h>
#include <X11/Xlib.h>
#include <X11/Xutil.h>

#include <cairo.h>
#include <cairo-xlib.h>
#include <unistd.h>

int main(int argc, char** argv) {
    Display *display = XOpenDisplay(NULL);
    if (display == NULL) {
        fprintf(stderr, "Unable to open X display\n");
        return EXIT_FAILURE;
    }

    Window root = DefaultRootWindow(display);
    XImage* image;

    Window *children, parent;
    unsigned int nchildren;

    XQueryTree(display, root, &root, &parent, &children, &nchildren);
    
    for (unsigned int i = 0; i < nchildren; i++) {
        char* name;
        XFetchName(display, children[i], &name);
        printf("Fetched name\n");
        if (name) {
            printf("%s\n", name);
            continue;
        }

        XWindowAttributes attr = {};
        XGetWindowAttributes(display, children[i], &attr);

        int width = attr.width;
        int height = attr.height;

        if (width <= 0 || height <= 0 || attr.map_state != IsViewable) {
            printf("Skipping\n");
            XFree(name);
            continue;
        }

        image = XGetImage(display, children[i], 0, 0, width, height, AllPlanes, ZPixmap);
        cairo_surface_t *surface = cairo_image_surface_create(CAIRO_FORMAT_ARGB32, width, height);
        unsigned char *data = cairo_image_surface_get_data(surface);

        for (int y = 0; y < height; y++) {
            for (int x = 0; x < width; x++) {
                long pixel = XGetPixel(image, x, y);
                unsigned char red = (pixel & image->red_mask) >> 16;
                unsigned char green = (pixel & image->green_mask) >> 8;
                unsigned char blue = (pixel & image->blue_mask);

                int index = (y * width + x) * 4;
                data[index] = blue;
                data[index + 1] = green;
                data[index + 2] = red;
                data[index + 3] = 255;

                // usleep(10 * 1000); // We need to slow down the screenshotting to capture it with avml
            }
        }

        char buffer[1024];
        snprintf(buffer, sizeof(buffer), "screenshot_%d", i);
        cairo_status_t status = cairo_surface_write_to_png(surface, buffer);
        if (status != CAIRO_STATUS_SUCCESS) {
            fprintf(stderr, "Failed to write PNG: %s\n", cairo_status_to_string(status));
        }

        cairo_surface_destroy(surface);
        // XFree(name);
        XDestroyImage(image);
    }
    XCloseDisplay(display);
    return EXIT_SUCCESS;
}
