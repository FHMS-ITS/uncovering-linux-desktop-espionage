#include <errno.h>
#include <fcntl.h>
#include <linux/videodev2.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

#define FRAME_COUNT 1000

typedef struct {
    void *start;
    size_t length;
} Buffer;

int main() {
    const char *device = "/dev/video0";
    int fd = open(device, O_RDWR);
    if (fd < 0) {
        perror("Failed to open video device");
        return 1;
    }

    struct v4l2_capability cap;
    if (ioctl(fd, VIDIOC_QUERYCAP, &cap) < 0) {
        perror("Failed to query device capabilities");
        close(fd);
        return 1;
    }

    if (!(cap.capabilities & V4L2_CAP_VIDEO_CAPTURE)) {
        fprintf(stderr, "Device does not support video capture\n");
        close(fd);
        return 1;
    }

    struct v4l2_format fmt;
    memset(&fmt, 0, sizeof(fmt));
    fmt.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    fmt.fmt.pix.width = 640; 
    fmt.fmt.pix.height = 480;
    fmt.fmt.pix.pixelformat = V4L2_PIX_FMT_YUYV;
    fmt.fmt.pix.field = V4L2_FIELD_INTERLACED;

    if (ioctl(fd, VIDIOC_S_FMT, &fmt) < 0) {
        perror("Failed to set video format");
        close(fd);
        return 1;
    }

    struct v4l2_requestbuffers req;
    memset(&req, 0, sizeof(req));
    req.count = 4;
    req.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    req.memory = V4L2_MEMORY_MMAP;

    if (ioctl(fd, VIDIOC_REQBUFS, &req) < 0) {
        perror("Failed to request buffers");
        close(fd);
        return 1;
    }

    Buffer *buffers = calloc(req.count, sizeof(Buffer));
    for (size_t i = 0; i < req.count; i++) {
        struct v4l2_buffer buf;
        memset(&buf, 0, sizeof(buf));
        buf.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
        buf.memory = V4L2_MEMORY_MMAP;
        buf.index = i;

        if (ioctl(fd, VIDIOC_QUERYBUF, &buf) < 0) {
            perror("Failed to query buffer");
            close(fd);
            free(buffers);
            return 1;
        }

        buffers[i].length = buf.length;
        buffers[i].start = mmap(NULL, buf.length, PROT_READ | PROT_WRITE,
                                MAP_SHARED, fd, buf.m.offset);

        if (buffers[i].start == MAP_FAILED) {
            perror("Failed to map buffer");
            close(fd);
            free(buffers);
            return 1;
        }
    }

    for (size_t i = 0; i < req.count; i++) {
        struct v4l2_buffer buf;
        memset(&buf, 0, sizeof(buf));
        buf.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
        buf.memory = V4L2_MEMORY_MMAP;
        buf.index = i;

        if (ioctl(fd, VIDIOC_QBUF, &buf) < 0) {
            perror("Failed to queue buffer");
            close(fd);
            free(buffers);
            return 1;
        }
    }

    enum v4l2_buf_type type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    if (ioctl(fd, VIDIOC_STREAMON, &type) < 0) {
        perror("Failed to start stream");
        close(fd);
        free(buffers);
        return 1;
    }

    FILE *output = fopen("video.raw", "wb");
    if (!output) {
        perror("Failed to open output file");
        close(fd);
        free(buffers);
        return 1;
    }

    for (int i = 0; i < FRAME_COUNT; i++) {
        struct v4l2_buffer buf;
        memset(&buf, 0, sizeof(buf));
        buf.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
        buf.memory = V4L2_MEMORY_MMAP;

        if (ioctl(fd, VIDIOC_DQBUF, &buf) < 0) {
            perror("Failed to dequeue buffer");
            break;
        }

        fwrite(buffers[buf.index].start, 1, buf.bytesused, output);

        if (ioctl(fd, VIDIOC_QBUF, &buf) < 0) {
            perror("Failed to requeue buffer");
            break;
        }
    }

    fclose(output);
    ioctl(fd, VIDIOC_STREAMOFF, &type);
    close(fd);
    free(buffers);

    printf("Video saved to 'video.raw'\n");
    return 0;
}
