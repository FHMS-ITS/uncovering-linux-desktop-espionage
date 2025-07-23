#include <portaudio.h>
#include <stdio.h>
#include <stdlib.h>

#define SAMPLE_RATE 44100
#define FRAMES_PER_BUFFER 512
#define NUM_SECONDS 15
#define NUM_CHANNELS 1
#define SAMPLE_FORMAT paInt16 // 16-bit audio

typedef short SAMPLE;

typedef struct {
    SAMPLE *buffer;
    size_t max_samples;
    size_t current_index;
} RecordData;

static int recordCallback(const void *inputBuffer, void *outputBuffer,
                          unsigned long framesPerBuffer,
                          const PaStreamCallbackTimeInfo *timeInfo,
                          PaStreamCallbackFlags statusFlags, void *userData) {
    RecordData *data = (RecordData *)userData;
    const SAMPLE *input = (const SAMPLE *)inputBuffer;

    if (input == NULL) {
        printf("No input!\n");
        return paComplete;
    }

    size_t samples_to_copy = framesPerBuffer;
    if (data->current_index + samples_to_copy > data->max_samples) {
        samples_to_copy = data->max_samples - data->current_index;
    }

    for (size_t i = 0; i < samples_to_copy; i++) {
        data->buffer[data->current_index++] = input[i];
    }

    return (data->current_index >= data->max_samples) ? paComplete : paContinue;
}

int main() {
    PaStream *stream;
    PaError err;

    size_t total_samples = SAMPLE_RATE * NUM_SECONDS * NUM_CHANNELS;
    SAMPLE *recorded_samples = (SAMPLE *)malloc(total_samples * sizeof(SAMPLE));
    if (recorded_samples == NULL) {
        fprintf(stderr, "Could not allocate memory for recording buffer.\n");
        return 1;
    }

    RecordData data = {recorded_samples, total_samples, 0};

    err = Pa_Initialize();
    if (err != paNoError) {
        fprintf(stderr, "PortAudio error: %s\n", Pa_GetErrorText(err));
        free(recorded_samples);
        return 1;
    }

    err = Pa_OpenDefaultStream(&stream,
                               NUM_CHANNELS, // Input channels
                               0,            // Output channels
                               SAMPLE_FORMAT, SAMPLE_RATE, FRAMES_PER_BUFFER,
                               recordCallback, &data);
    if (err != paNoError) {
        fprintf(stderr, "PortAudio error: %s\n", Pa_GetErrorText(err));
        free(recorded_samples);
        Pa_Terminate();
        return 1;
    }

    err = Pa_StartStream(stream);
    if (err != paNoError) {
        fprintf(stderr, "PortAudio error: %s\n", Pa_GetErrorText(err));
        free(recorded_samples);
        Pa_CloseStream(stream);
        Pa_Terminate();
        return 1;
    }

    printf("Recording for %d seconds...\n", NUM_SECONDS);
    while (Pa_IsStreamActive(stream)) {
        Pa_Sleep(100);
    }

    err = Pa_StopStream(stream);
    if (err != paNoError) {
        fprintf(stderr, "PortAudio error: %s\n", Pa_GetErrorText(err));
    }

    Pa_CloseStream(stream);
    Pa_Terminate();

    FILE *file = fopen("audio_port.raw", "wb");
    if (file != NULL) {
        fwrite(recorded_samples, sizeof(SAMPLE), data.current_index, file);
        fclose(file);
    } else {
        fprintf(stderr, "Could not open file for writing.\n");
    }

    free(recorded_samples);
    return 0;
}
