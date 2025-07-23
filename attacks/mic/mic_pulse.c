#include <pulse/error.h>
#include <pulse/pulseaudio.h>
#include <pulse/sample.h>
#include <pulse/simple.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#define SAMPLE_RATE 44100
#define CHANNELS 2
#define SECONDS 15
#define BUFSIZE 4096

int main() {
    static const pa_sample_spec ss = {
        .format = PA_SAMPLE_S16LE, // we record at 16 little endian but need to
                                   // play at 32 (?)
        .rate = SAMPLE_RATE,
        .channels = CHANNELS};

    if (!pa_sample_spec_valid(&ss)) {
        fprintf(stderr, "Invalid sample spec\n");
        return 1;
    }

    int error;
    pa_simple *s = pa_simple_new(NULL, "PulseAudioRecorder", PA_STREAM_RECORD,
                                 NULL, "record", &ss, NULL, NULL, &error);
    if (!s) {
        fprintf(stderr, "pa_simple_new() failed: %s\n", pa_strerror(error));
        return 1;
    }

    FILE *output = fopen("audio_pulse.raw", "wb");
    if (!output) {
        perror("Failed to open output file");
        pa_simple_free(s);
        return 1;
    }

    struct timespec start, current;
    clock_gettime(CLOCK_MONOTONIC, &start);

    for (;;) {
        uint8_t buf[BUFSIZE];

        if (pa_simple_read(s, buf, sizeof(buf), &error) < 0) {
            fprintf(stderr, "pa_simple_read() failed: %s\n",
                    pa_strerror(error));
            fclose(output);
            pa_simple_free(s);
            return 1;
        }

        if (fwrite(buf, 1, sizeof(buf), output) != sizeof(buf)) {
            perror("Failed to write data to file");
            fclose(output);
            pa_simple_free(s);
            return 1;
        }

        clock_gettime(CLOCK_MONOTONIC, &current);
        double elapsed = (current.tv_sec - start.tv_sec) +
                         (current.tv_nsec - start.tv_nsec) / 1e9;
        if (elapsed >= SECONDS) {
            printf("Recording stopped after %.2f seconds\n", elapsed);
            break;
        }
    }

    fclose(output);
    pa_simple_free(s);

    return 0;
}
