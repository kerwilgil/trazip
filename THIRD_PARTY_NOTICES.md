# Third-party notices

## github.com/hunydev/g729

TRAZIP uses `github.com/hunydev/g729` **v0.2.3-rc5**, pinned to commit
`302ae2b7bc9436dca324b3bf3d6aff54f4fa1a7f`, solely through the internal
`internal/voip/audio_g729.go` adapter for G.729 decoding.

License: MIT. The upstream license text and source are available at the pinned
revision: https://github.com/hunydev/g729/blob/302ae2b7bc9436dca324b3bf3d6aff54f4fa1a7f/LICENSE

The integration uses `Decoder.DecodeFrame` only. It does not use experimental
enhanced decoding APIs, CGO, DLLs, FFmpeg, bcg729, or gobcg729.
