"""Password generation.

Two modes, because the Beepy changes the calculus.

**Full** uses letters, digits and symbols, for passwords you will only ever paste.

**Thumb** drops the symbol classes. On the Beepy's BBQ20 keyboard, symbols sit
behind a modifier layer, so a password full of them is genuinely unpleasant to type
on a device you hold in one hand. Since length buys more strength per unit effort
than character variety does, a longer thumb-typable password is the better trade:
``base62`` at 20 characters is about 119 bits, well beyond ``base94`` at 12
characters (about 79 bits).

Both modes exclude visually ambiguous characters by default, because these get
transcribed by hand and read off a 400x240 monochrome screen where ``l``, ``1`` and
``I`` are hard to tell apart.

Everything uses :mod:`secrets`, never :mod:`random`.
"""

from __future__ import annotations

import math
import secrets
import string
from dataclasses import dataclass

__all__ = [
    "GeneratorError",
    "Alphabet",
    "generate",
    "generate_passphrase",
    "entropy_bits",
    "AMBIGUOUS",
    "SYMBOLS",
]

AMBIGUOUS = "lI1O0o"
"""Characters that get misread on a small monochrome screen or in handwriting."""

SYMBOLS = "!#$%&*+-=?@^_"
"""A conservative symbol set.

Excludes quotes, backslash, backtick, and the shell metacharacters that cause
trouble when a password is pasted into a config file or a command line.
"""


class GeneratorError(Exception):
    pass


@dataclass(frozen=True, slots=True)
class Alphabet:
    name: str
    characters: str

    def __len__(self) -> int:
        return len(self.characters)


def build_alphabet(
    *,
    thumb: bool = False,
    digits: bool = True,
    symbols: bool = True,
    allow_ambiguous: bool = False,
) -> Alphabet:
    """Assemble the character set.

    ``thumb`` forces symbols off; that is the whole point of the mode.
    """
    characters = string.ascii_lowercase + string.ascii_uppercase
    if digits:
        characters += string.digits
    if symbols and not thumb:
        characters += SYMBOLS

    if not allow_ambiguous:
        characters = "".join(c for c in characters if c not in AMBIGUOUS)

    if len(set(characters)) < 2:
        raise GeneratorError("the alphabet needs at least two distinct characters")

    name = "thumb" if thumb else "full"
    return Alphabet(name=name, characters="".join(sorted(set(characters))))


def entropy_bits(alphabet_size: int, length: int) -> float:
    if alphabet_size < 2 or length < 1:
        return 0.0
    return length * math.log2(alphabet_size)


def generate(
    length: int = 20,
    *,
    thumb: bool = False,
    digits: bool = True,
    symbols: bool = True,
    allow_ambiguous: bool = False,
    require_each_class: bool = True,
) -> str:
    """Generate a password.

    ``require_each_class`` retries until at least one character from each requested
    class is present, which is about satisfying websites that demand it rather than
    about strength. It is a rejection sample rather than a "place one of each and
    shuffle the rest" construction, because the latter subtly biases positions.
    """
    if length < 4:
        raise GeneratorError("length must be at least 4")
    if length > 512:
        raise GeneratorError("length must be at most 512")

    alphabet = build_alphabet(
        thumb=thumb,
        digits=digits,
        symbols=symbols,
        allow_ambiguous=allow_ambiguous,
    )
    pool = alphabet.characters

    wanted: list[str] = [
        "".join(c for c in string.ascii_lowercase if c in pool),
        "".join(c for c in string.ascii_uppercase if c in pool),
    ]
    if digits:
        wanted.append("".join(c for c in string.digits if c in pool))
    if symbols and not thumb:
        wanted.append("".join(c for c in SYMBOLS if c in pool))
    wanted = [group for group in wanted if group]

    # With length >= 4 and this many classes, acceptance is high; the bound only
    # exists so a pathological alphabet cannot spin forever.
    for _ in range(10_000):
        candidate = "".join(secrets.choice(pool) for _ in range(length))
        if not require_each_class:
            return candidate
        if all(any(c in group for c in candidate) for group in wanted):
            return candidate

    raise GeneratorError(
        "could not satisfy the character class requirements; try a longer password "
        "or pass require_each_class=False"
    )


# Word list for passphrases: short, lowercase, unambiguous in spelling, and easy
# both to type on a thumb keyboard and to read off a monochrome screen.
#
# Size matters directly and is asserted by a test. An earlier version of this list
# had 146 words, giving only 7.2 bits each, which made a 5-word phrase 36 bits --
# far too weak for a master password, and less than the docstring claimed. The list
# below is large enough that the documented figures are real.
#
# This is not the EFF long list (7776 words, 12.9 bits each). If you want more per
# word, use `diceware` or KeePassXC's generator and paste the result in. What is
# guaranteed here is that the number `pipw gen -p` prints is the true figure.
WORDS = (
    "abbey acorn acre adobe agate alcove alder algae almond alpine amber amble anchor "
    "anvil apex apple apricot apron arbor arcade arch archer arctic arena argon armour "
    "arrow ash ashen aspen asphalt aster atlas atoll attic auburn auger autumn avenue "
    "awning axis azure badge badger balcony bale balsa bamboo banner barge bark barley "
    "barn barrel basalt basil basin basket bastion bay bayou beach beacon beam bean "
    "bearing bedrock beech beetle bellows belfry bench bergamot berry birch bishop "
    "bison bittern blanket blossom bluff boathouse bobbin bolster bonnet border borough "
    "bottle boulder bouquet bowline bracken bramble branch brass bravo breeze brick "
    "bridge bridle brine bristle broadleaf bronze brook broom buckle buffer bugle "
    "bulwark bunker burlap burrow butane butter buttress cabbage cabin cable cactus "
    "cadence cairn caliper camber camphor canal candle canopy canteen canvas canyon "
    "capstan caravan cardamom cargo carob carpet cascade casement cashew casket "
    "castle catkin cattail causeway cavern cedar cellar cement census chalice "
    "chalk chamber channel chapel charcoal chart chasm chateau cheddar chestnut "
    "chevron chimney chisel chowder cider cinder cinnamon cistern citadel citrus "
    "clamp clapboard clay clearing clematis clever cliff clipper cloister clover "
    "cobalt cobble cocoa compass conch conduit conifer console copper copse coral "
    "cordage cork cornice corral cottage cotton cove cranberry crane crater crayon "
    "creek crescent crest cricket crimson crocus crossbar crowbar crumble crystal "
    "cupboard curb currant cushion cutlass cymbal cypress dahlia dairy damask damson "
    "dapple dashboard dawn daybreak dayglow deck delta denim derrick desert dewdrop "
    "diagram diamond diesel dinghy dogwood dolomite domain dormer dovetail downpour "
    "drawbridge dresser drizzle drumlin dryad dune dusk dynamo eagle earthen easel "
    "ebony echo eddy edge egret elder elm ember emerald enamel engine ermine escarp "
    "estuary ether evergreen fable facade fairway falcon fallow fathom feather fence "
    "fennel fern ferry fescue fiddle fig filament finch fireside firth fissure "
    "flagstone flamingo flannel flask flax fleece flint florin flotilla flourish "
    "flume flute foghorn foliage footbridge forest forge fossil foundry fountain "
    "foxglove freckle frigate fringe frost fulcrum funnel furrow gable gallery "
    "gangway gantry garden garnet gasket gateway gazebo gearbox gemstone geode "
    "geyser gingham girder glacier glade glass glean glen gneiss goblet gorge "
    "gossamer gourd granary granite grapevine graphite gravel grebe greenhouse "
    "grotto grove guava gully gunwale gypsum hackberry hamlet hammock hangar harbour "
    "hardwood harrow harvest hatchway hawthorn hayfield hazel headland hearth "
    "heather hedge helm hemlock herald herring hickory hillside hinge hoarfrost "
    "hollow homestead honeydew hoop hopper hornbeam horseshoe hostel hurdle hyacinth "
    "iceberg icicle igloo incense indigo inlet ironwood island isthmus ivory jackdaw "
    "jade jasmine jasper jetty jonquil juniper kapok kayak keelson kelp kerosene "
    "kestrel kettle keystone kiln kingfisher kiosk kite knapsack knoll lacquer ladder "
    "lagoon lakeshore lambda lamppost lancet landmark lantern lapis larch lark "
    "lattice laurel lavender ledge lemon lentil levee lever lichen lighthouse lilac "
    "linden linen lintel lobster lockbox locust lodestone loft loganberry loom "
    "lookout lumber lupine lyre macadam mackerel madder magnet magnolia mahogany "
    "maize mallet mandolin mangrove mantel maple marble marigold marina marjoram "
    "marker marmot marsh mast matrix meadow medley melon menhir merchant meridian "
    "mesa mesquite metaphor mezzanine midland milestone millet mineral mint mirage "
    "mist mistral moat molasses monsoon moraine mortar mosaic moss mulberry mullet "
    "muslin myrrh myrtle nacre nautilus nectar needle nettle nickel nimbus nutmeg "
    "oaken oasis obelisk obsidian ochre octave offshore olive onyx opal orchard "
    "orchid organ osprey ottoman outcrop outpost overhang oxbow oyster paddle "
    "paddock pagoda pallet palmetto pampas pantry papaya papyrus parapet parchment "
    "parsley partridge pastel pasture pathway patio pavilion peacock pearl peat "
    "pebble pelican pendant penguin pennant peony pepper pergola periwinkle petal "
    "pewter pheasant piazza picket piedmont pier pigment pilaster pillar pimento "
    "pinnacle pioneer pipit piston pitcher placard plane plankton plateau platinum "
    "plaza plover plum plumbago plywood pocket polestar pollen pomelo poncho pond "
    "poplar poppy porcelain portal portico postern pottery prairie primrose prism "
    "promenade propeller prow pumice pumpkin purslane pylon pyramid quadrant quagmire "
    "quarry quartz quay quill quilt quince rafter rampart ranch rapids raspberry "
    "rattan ravine rayon redwood reef reservoir resin retaining rhubarb ribbon ridge "
    "rigging rill rivet roadstead rockery rookery rosemary rosewood rotunda rowan "
    "rubble rudder runnel rushes russet rutabaga saffron sagebrush sailcloth "
    "salamander salt samphire sandbar sandstone sapling sapphire sardine sash "
    "sassafras satchel savanna sawmill scaffold scallop scarlet schooner sconce "
    "scrapyard sculpture seabed seagrass seam seaport sedge selvage sepal sepia "
    "sequoia serpentine shale shallot shanty shelter shingle shipyard shoal shutter "
    "sienna sierra silhouette sill silo silt silver sinew siskin skerry skylight "
    "slate sleeve slipway sloop smelter snapdragon snowdrift socket sodium soffit "
    "solder sorrel spandrel spar speedwell sphinx spinnaker spiral spire spool "
    "sprocket spruce spur squall stables stairwell stalactite stanchion staple "
    "starboard starling steeple stencil steppe sternum stipple stockade stonework "
    "stopwatch storeroom stratum stucco stubble stumpwood sundial sunflower surf "
    "sussex swale swallow swamp sycamore syrup tabard tackle taffeta talus tamarack "
    "tamarind tambour tangerine tannin tapestry tarmac tarragon teak teal telescope "
    "tenon terrace terrapin thatch thicket thimble thistle thorn threshold thrush "
    "thyme tidal timber tinder toadflax toboggan tollgate topaz topsail torrent "
    "tortoise tower townhouse trailhead trapdoor travertine treadle trefoil trellis "
    "tributary trident trolley trombone trough trowel truffle trundle tulip tundra "
    "tungsten tunnel turbine turnstile turpentine turquoise turret tussock twine "
    "umber upland uranium vale valley valve vane vanilla vault veldt vellum velvet "
    "veneer verbena verdant vertex vessel vestibule viaduct village vineyard viola "
    "violet vireo vista volcano voyage wagon wainscot walnut warbler wardroom "
    "warehouse warren washboard watercress waterfall watermark wattle wavelet wayside "
    "weathervane weir welkin wharf wheatfield whetstone whinchat whirlpool whistle "
    "wicker wigwam wildwood willow windlass windmill windrow wisteria witchhazel "
    "woodland woodruff workbench workshop wreath wrenchbox yardarm yarrow yellowwood "
    "yew yucca zenith zephyr zinnia zircon"
).split()
WORDS = tuple(sorted(set(WORDS)))
"""Deduplicated and frozen at import.

Uniqueness is enforced here rather than trusted to careful typing: a repeated
word would make some choices twice as likely as others and make the entropy
figure printed by ``pipw gen -p`` an overstatement.
"""


BITS_PER_WORD = math.log2(len(WORDS))


def generate_passphrase(words: int = 6, separator: str = "-") -> str:
    """Generate a word-sequence passphrase.

    This is what to use for the **master password**. Argon2id at 64 MiB buys perhaps
    10-20 bits of work factor against an attacker with fast hardware, so the
    passphrase's own entropy is what actually carries the security.

    Each word contributes :data:`BITS_PER_WORD` bits, so the default six words is
    about 59 bits, and eight words about 79. Unlike a short symbol-heavy string,
    this is realistic to type on a thumb keyboard and to remember.

    The exact figure is computed, never hard-coded, and ``pipw gen -p`` prints it.
    """
    if words < 3:
        raise GeneratorError("use at least three words")
    if words > 32:
        raise GeneratorError("use at most thirty-two words")
    return separator.join(secrets.choice(WORDS) for _ in range(words))
