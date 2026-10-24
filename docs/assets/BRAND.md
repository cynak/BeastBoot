# beast-booter colours

One palette for everything people see: the desktop app
(`installer/beastbooter/gui/theme.py`), the boot menu theme
(`build/theme/mktheme.py`) and the README hero cards (`hero-dark.svg`,
`hero-light.svg`). Dark grey surfaces, one red accent. Change a colour here
first, then in those three places.

## Greys (a neutral zinc, very slightly cool)

| Token | Hex | Used for (dark UI) |
|---|---|---|
| grey-950 | `#0F0F10` | deepest: log and text fields, console box |
| grey-900 | `#141415` | window / screen background |
| grey-850 | `#1A1A1C` | title bar, panels |
| grey-800 | `#1F1F22` | cards |
| grey-750 | `#26262A` | hover, normal buttons |
| grey-700 | `#2F2F33` | card borders, pressed |
| grey-600 | `#3D3D42` | field and button borders, scrollbar thumb |
| grey-500 | `#5C5C63` | disabled text |
| grey-400 | `#9A9AA2` | muted text (footers, hints) |
| grey-300 | `#CFCFD4` | secondary text, line icons |
| grey-100 | `#F2F2F3` | primary text, titles |

Light UI greys: background `#F5F5F6`, cards `#FFFFFF`, card borders
`#E1E1E4`, field / button borders `#C6C6CC`, text `#18181B`, secondary
text `#3F3F46`, muted `#63636B`, disabled `#A1A1AA`.

## Red (the accent)

| Token | Hex | Used for |
|---|---|---|
| red-300 | `#FF8A93` | accent text and focus rings on dark |
| red-400 | `#F0505E` | highlights on dark: selection border, progress bar, focus |
| red-500 | `#DD3344` | hover of the primary button (white text on it: 4.53:1) |
| red-600 | `#D62839` | **the accent**: primary buttons, selected-item border, logo body (white text on it: 4.97:1) |
| red-700 | `#B01E2E` | pressed; accent text on light backgrounds (6.9:1 on white) |
| red-800 | `#7A1622` | deep: selection fill on dark, logo body shade |
| red-950 | `#2A1215` | red-tinted dark surface: the selected card |
| red-50 / red-100 | `#FDECEE` / `#F9D2D7` | red-tinted light surfaces (light UI) |

Two surfaces are deliberately not plain red tints, so they don't look like a
selected item: info boxes are a warm grey (dark `#231A1C`, border `#42282C`;
light `#FCF4F5`, border `#F3D9DC`), and the light UI's selected card is
`#FEF1F2` (amber warning text on it stays above 4.5:1).

## Meaning colours (unchanged roles)

- **Danger** (erase, destructive): `#B42318` (hover `#C6362A`, pressed
  `#8F1C13`), text on dark `#FF8A80`, box on dark `#2B1311` / border
  `#7A1F1A`; on light text `#B42318`, box `#FEF3F2` / border `#FDA29B`. It is a
  darker, warmer brick than the accent and always comes with a warning icon
  and words, so a destructive button never looks like an ordinary one.
- **OK** `#10B981` (text on dark `#34D399`), **warning** `#F59E0B` (text on
  dark `#FBBF24`): as before.
- Distribution logo colours in the boot menu (Ubuntu orange, Debian red, ...)
  stay the distributions' own.
