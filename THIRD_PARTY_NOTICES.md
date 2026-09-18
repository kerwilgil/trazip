# Third-party notices

TRAZIP incorpora componentes de terceros en su forma compilada/embebida. Este
documento cumple la obligación de aviso de las licencias de dichos componentes,
cuyos textos completos se acompañan bajo `THIRD_PARTY_LICENSES/`.

Estos componentes conservan sus propias licencias. Nada en la licencia de TRAZIP
restringe los derechos que esas licencias conceden sobre dichos componentes.

Método de derivación: `go list -deps` sobre los tres binarios distribuidos
(`trazip`, `trazip-updater`, `tzsp-sender`) + verificación `go version -m` sobre
los binarios compilados, y análisis del bundle de `frontend/dist` (build real).
Solo se listan componentes efectivamente redistribuidos. Las herramientas de
build/test (Vite, TypeScript, Vitest, ESLint, Rollup, esbuild, etc.) no se
redistribuyen y por tanto no requieren aviso en el producto distribuido.

## A. Componentes Go enlazados en los ejecutables

| COMPONENT | VERSION | LICENSE | COPYRIGHT | SOURCE | DISTRIBUTION_CLASS | NOTICE_REQUIREMENT |
|---|---|---|---|---|---|---|
| codeberg.org/miekg/dns | v0.6.84 | BSD-3-Clause | Copyright (c) 2009, The Go Authors. Extensions copyright (c) 2011, Miek Gieben. | codeberg.org/miekg/dns | LINKED_IN_BINARY | incluir texto de licencia + copyright (LICENSE -> THIRD_PARTY_LICENSES/codeberg.org__miekg__dns.LICENSE.txt) |
| git.sr.ht/~jackmordaunt/go-toast/v2 | v2.0.3 | Unlicense OR MIT (dual; SPDX-License-Identifier exacto del upstream) | Copyright (c) 2023 Jack Mordaunt | git.sr.ht/~jackmordaunt/go-toast/v2 | LINKED_IN_BINARY | incluir texto de licencia + copyright (LICENSE -> THIRD_PARTY_LICENSES/git.sr.ht__~jackmordaunt__go-toast__v2.LICENSE.txt; el archivo contiene íntegros el encabezado dual y ambos textos: Unlicense y MIT) |
| github.com/google/uuid | v1.6.0 | BSD-3-Clause | Copyright (c) 2009,2014 Google Inc. All rights reserved. | https://github.com/google/uuid | LINKED_IN_BINARY | incluir texto de licencia + copyright (LICENSE -> THIRD_PARTY_LICENSES/github.com__google__uuid.LICENSE.txt) |
| github.com/go-ole/go-ole | v1.3.0 | MIT | Copyright © 2013-2017 Yasuhiro Matsumoto, <mattn.jp@gmail.com> | https://github.com/go-ole/go-ole | LINKED_IN_BINARY | incluir texto de licencia + copyright (LICENSE -> THIRD_PARTY_LICENSES/github.com__go-ole__go-ole.LICENSE.txt) |
| github.com/gopacket/gopacket | v1.7.0 | BSD-3-Clause | Copyright (c) 2012 Google, Inc. All rights reserved. | https://github.com/gopacket/gopacket | LINKED_IN_BINARY | incluir texto de licencia + copyright (LICENSE -> THIRD_PARTY_LICENSES/github.com__gopacket__gopacket.LICENSE.txt) |
| github.com/gorilla/websocket | v1.5.3 | BSD-2-Clause | Copyright (c) 2013 The Gorilla WebSocket Authors. All rights reserved. | https://github.com/gorilla/websocket | LINKED_IN_BINARY | incluir texto de licencia + copyright (LICENSE -> THIRD_PARTY_LICENSES/github.com__gorilla__websocket.LICENSE.txt) |
| github.com/hunydev/g729 | v0.2.3-rc5 | MIT | Copyright (c) 2026 g729 authors | https://github.com/hunydev/g729 | LINKED_IN_BINARY | incluir texto de licencia + copyright (LICENSE -> THIRD_PARTY_LICENSES/github.com__hunydev__g729.LICENSE.txt) |
| github.com/leaanthony/go-ansi-parser | v1.6.1 | MIT | Copyright (c) 2021-Present Lea Anthony | https://github.com/leaanthony/go-ansi-parser | LINKED_IN_BINARY | incluir texto de licencia + copyright (LICENSE -> THIRD_PARTY_LICENSES/github.com__leaanthony__go-ansi-parser.LICENSE.txt) |
| github.com/leaanthony/slicer | v1.6.0 | MIT | Copyright (c) 2019 Lea Anthony | https://github.com/leaanthony/slicer | LINKED_IN_BINARY | incluir texto de licencia + copyright (LICENSE -> THIRD_PARTY_LICENSES/github.com__leaanthony__slicer.LICENSE.txt) |
| github.com/leaanthony/u | v1.1.1 | MIT | Copyright (c) 2023-Present Lea Anthony | https://github.com/leaanthony/u | LINKED_IN_BINARY | incluir texto de licencia + copyright (LICENSE -> THIRD_PARTY_LICENSES/github.com__leaanthony__u.LICENSE.txt) |
| github.com/nyaruka/phonenumbers | v1.8.1 | MIT | Copyright (c) 2017-2022 Trey Tacon, Nyaruka | https://github.com/nyaruka/phonenumbers | LINKED_IN_BINARY | incluir texto de licencia + copyright (LICENSE -> THIRD_PARTY_LICENSES/github.com__nyaruka__phonenumbers.LICENSE.txt) |
| github.com/oschwald/maxminddb-golang/v2 | v2.4.1 | ISC | Copyright (c) 2015, Gregory J. Oschwald <oschwald@gmail.com> | https://github.com/oschwald/maxminddb-golang/v2 | LINKED_IN_BINARY | incluir texto de licencia + copyright (LICENSE -> THIRD_PARTY_LICENSES/github.com__oschwald__maxminddb-golang__v2.LICENSE.txt) |
| github.com/pkg/errors | v0.9.1 | BSD-2-Clause | Copyright (c) 2015, Dave Cheney <dave@cheney.net> | https://github.com/pkg/errors | LINKED_IN_BINARY | incluir texto de licencia + copyright (LICENSE -> THIRD_PARTY_LICENSES/github.com__pkg__errors.LICENSE.txt) |
| github.com/rivo/uniseg | v0.4.7 | MIT | Copyright (c) 2019 Oliver Kuederle | https://github.com/rivo/uniseg | LINKED_IN_BINARY | incluir texto de licencia + copyright (LICENSE.txt -> THIRD_PARTY_LICENSES/github.com__rivo__uniseg.LICENSE.txt) |
| github.com/wailsapp/go-webview2 | v1.0.22 | MIT | Copyright (c) 2020 John Chadwick | https://github.com/wailsapp/go-webview2 | LINKED_IN_BINARY | incluir texto de licencia + copyright (LICENSE -> THIRD_PARTY_LICENSES/github.com__wailsapp__go-webview2.LICENSE.txt) |
| github.com/wailsapp/wails/v2 | v2.13.0 | MIT | Copyright (c) 2018-Present Lea Anthony | https://github.com/wailsapp/wails/v2 | LINKED_IN_BINARY | incluir texto de licencia + copyright (LICENSE -> THIRD_PARTY_LICENSES/github.com__wailsapp__wails__v2.LICENSE.txt) |
| golang.org/x/crypto | v0.53.0 | BSD-3-Clause | Copyright 2009 The Go Authors. | golang.org/x/crypto | LINKED_IN_BINARY | incluir texto de licencia + copyright (LICENSE -> THIRD_PARTY_LICENSES/golang.org__x__crypto.LICENSE.txt) |
| golang.org/x/net | v0.56.0 | BSD-3-Clause | Copyright 2009 The Go Authors. | golang.org/x/net | LINKED_IN_BINARY | incluir texto de licencia + copyright (LICENSE -> THIRD_PARTY_LICENSES/golang.org__x__net.LICENSE.txt) |
| golang.org/x/sys | v0.46.0 | BSD-3-Clause | Copyright 2009 The Go Authors. | golang.org/x/sys | LINKED_IN_BINARY | incluir texto de licencia + copyright (LICENSE -> THIRD_PARTY_LICENSES/golang.org__x__sys.LICENSE.txt) |
| golang.org/x/text | v0.38.0 | BSD-3-Clause | Copyright 2009 The Go Authors. | golang.org/x/text | LINKED_IN_BINARY | incluir texto de licencia + copyright (LICENSE -> THIRD_PARTY_LICENSES/golang.org__x__text.LICENSE.txt) |
| google.golang.org/protobuf | v1.36.11 | BSD-3-Clause | Copyright (c) 2018 The Go Authors. All rights reserved. | google.golang.org/protobuf | LINKED_IN_BINARY | incluir texto de licencia + copyright (LICENSE -> THIRD_PARTY_LICENSES/google.golang.org__protobuf.LICENSE.txt) |

## B. Componentes del frontend embebidos en el bundle

| COMPONENT | VERSION | LICENSE | COPYRIGHT | SOURCE | DISTRIBUTION_CLASS | NOTICE_REQUIREMENT |
|---|---|---|---|---|---|---|
| @fontsource-variable/inter | 5.2.8 | OFL-1.1 | Copyright 2016 The Inter Project Authors (https://github.com/rsms/inter) | https://github.com/fontsource/font-files/tree/main/fonts/variable/inter | RUNTIME_DISTRIBUTED | incluir texto de licencia + copyright (THIRD_PARTY_LICENSES/fontsource-variable__inter.LICENSE.txt) |
| react | 19.2.7 | MIT | Copyright (c) Meta Platforms, Inc. and affiliates. | https://github.com/facebook/react | RUNTIME_DISTRIBUTED | incluir texto de licencia + copyright (THIRD_PARTY_LICENSES/react.LICENSE.txt) |
| react-dom | 19.2.7 | MIT | Copyright (c) Meta Platforms, Inc. and affiliates. | https://github.com/facebook/react | RUNTIME_DISTRIBUTED | incluir texto de licencia + copyright (THIRD_PARTY_LICENSES/react-dom.LICENSE.txt) |
| scheduler | 0.27.0 | MIT | Copyright (c) Meta Platforms, Inc. and affiliates. | https://github.com/facebook/react | RUNTIME_DISTRIBUTED | incluir texto de licencia + copyright (THIRD_PARTY_LICENSES/scheduler.LICENSE.txt) |

### La fuente tipográfica Inter (OFL-1.1)

Los archivos `inter-*.woff2` embebidos son la fuente Inter, licenciada bajo la
SIL Open Font License 1.1. OFL-1.1 permite embeber y redistribuir la fuente junto
al software (incluido software comercial). Obligaciones cumplidas aquí: se incluye
el texto íntegro de OFL-1.1 y este aviso de copyright (2016 The Inter Project
Authors). La fuente no se vende por separado y no se crean derivados con nombres
reservados.

## C. Detalle de integración de github.com/hunydev/g729

TRAZIP uses `github.com/hunydev/g729` **v0.2.3-rc5**, pinned to commit
`302ae2b7bc9436dca324b3bf3d6aff54f4fa1a7f`, solely through the internal
`internal/voip/audio_g729.go` adapter for G.729 decoding.

License: MIT. The upstream license text and source are available at the pinned
revision: https://github.com/hunydev/g729/blob/302ae2b7bc9436dca324b3bf3d6aff54f4fa1a7f/LICENSE

The integration uses `Decoder.DecodeFrame` only. It does not use experimental
enhanced decoding APIs, CGO, DLLs, FFmpeg, bcg729, or gobcg729.

## D. Componentes externos NO redistribuidos (informativo)

Los siguientes componentes interactúan con TRAZIP en tiempo de ejecución pero
**no se incluyen** en los binarios ni en los paquetes de distribución:

| COMPONENT | LICENSE | RELACIÓN |
|---|---|---|
| Microsoft Edge WebView2 Runtime | Microsoft Software License Terms (Evergreen) | Prerequisito del sistema/instalador bootstrapper; no redistribuido por TRAZIP. |
| Npcap (npcap.com) | Npcap EULA | Driver prerequisito para captura en vivo; el usuario lo instala por separado; no se redistribuye. |
| Bases MaxMind GeoLite2 | GeoLite2 EULA / CC BY-SA 4.0 | Descargadas en runtime por la app; no se incluyen en el paquete. |
| Toolchain NSIS (makensis) | zlib/libpng | Solo herramienta de build; genera el stub del instalador. |

Conteo de entradas de aviso: 21 Go + 4 npm = 25 componentes redistribuidos.
