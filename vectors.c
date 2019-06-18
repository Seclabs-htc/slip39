#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "slip39.h"

#define MAX_MNEMONTIC_COUNT 8

struct _vectors {
    char *description;
    char *mnemonic[MAX_SAHRE_VALUE_LEN];
    char *secret;
} vectors[] =

{
  {
    "1. Valid mnemonic without sharing (128 bits)",
    {
      "duckling enlarge academic academic agency result length solution fridge kidney coal piece deal husband erode duke ajar critical decision keyboard",
      0
    },
    "bb54aac4b89dc868ba37d9cc21b2cece"
  },
  {
    "2. Mnemonic with invalid checksum (128 bits)",
    {
      "duckling enlarge academic academic agency result length solution fridge kidney coal piece deal husband erode duke ajar critical decision kidney",
      0
    },
    ""
  },
  {
    "3. Mnemonic with invalid padding (128 bits)",
    {
      "duckling enlarge academic academic email result length solution fridge kidney coal piece deal husband erode duke ajar music cargo fitness",
      0
    },
    ""
  },
  {
    "4. Basic sharing 2-of-3 (128 bits)",
    {
      "shadow pistol academic always adequate wildlife fancy gross oasis cylinder mustang wrist rescue view short owner flip making coding armed",
      "shadow pistol academic acid actress prayer class unknown daughter sweater depict flip twice unkind craft early superior advocate guest smoking",
      0
    },
    "b43ceb7e57a0ea8766221624d01b0864"
  },
  {
    "5. Basic sharing 2-of-3 (128 bits)",
    {
      "shadow pistol academic always adequate wildlife fancy gross oasis cylinder mustang wrist rescue view short owner flip making coding armed",
      0
    },
    ""
  },
  {
    "6. Mnemonics with different identifiers (128 bits)",
    {
      "adequate smoking academic acid debut wine petition glen cluster slow rhyme slow simple epidemic rumor junk tracks treat olympic tolerate",
      "adequate stay academic agency agency formal party ting frequent learn upstairs remember smear leaf damage anatomy ladle market hush corner",
      0
    },
    ""
  },
  {
    "7. Mnemonics with different iteration exponents (128 bits)",
    {
      "peasant leaves academic acid desert exact olympic math alive axle trial tackle drug deny decent smear dominant desert bucket remind",
      "peasant leader academic agency cultural blessing percent network envelope medal junk primary human pumps jacket fragment payroll ticket evoke voice",
      0
    },
    ""
  },
  {
    "8. Mnemonics with mismatching group thresholds (128 bits)",
    {
      "liberty category beard echo animal fawn temple briefing math username various wolf aviation fancy visual holy thunder yelp helpful payment",
      "liberty category beard email beyond should fancy romp founder easel pink holy hairy romp loyalty material victim owner toxic custody",
      "liberty category academic easy being hazard crush diminish oral lizard reaction cluster force dilemma deploy force club veteran expect photo",
      0
    },
    ""
  },
  {
    "9. Mnemonics with mismatching group counts (128 bits)",
    {
      "average senior academic leaf broken teacher expect surface hour capture obesity desire negative dynamic dominant pistol mineral mailman iris aide",
      "average senior academic agency curious pants blimp spew clothes slice script dress wrap firm shaft regular slavery negative theater roster",
      0
    },
    ""
  },
  {
    "10. Mnemonics with greater group threshold than group counts (128 bits)",
    {
      "music husband acrobat acid artist finance center either graduate swimming object bike medical clothes station aspect spider maiden bulb welcome",
      "music husband acrobat agency advance hunting bike corner density careful material civil evil tactics remind hawk discuss hobo voice rainbow",
      "music husband beard academic black tricycle clock mayor estimate level photo episode exclude ecology papa source amazing salt verify divorce",
      0
    },
    ""
  },
  {
    "11. Mnemonics with duplicate member indices (128 bits)",
    {
      "device stay academic always dive coal antenna adult black exceed stadium herald advance soldier busy dryer daughter evaluate minister laser",
      "device stay academic always dwarf afraid robin gravity crunch adjust soul branch walnut coastal dream costume scholar mortgage mountain pumps",
      0
    },
    ""
  },
  {
    "12. Mnemonics with mismatching member thresholds (128 bits)",
    {
      "hour painting academic academic device formal evoke guitar random modern justice filter withdraw trouble identify mailman insect general cover oven",
      "hour painting academic agency artist again daisy capital beaver fiber much enjoy suitable symbolic identify photo editor romp float echo",
      0
    },
    ""
  },
  {
    "13. Mnemonics giving an invalid digest (128 bits)",
    {
      "guilt walnut academic acid deliver remove equip listen vampire tactics nylon rhythm failure husband fatigue alive blind enemy teaspoon rebound",
      "guilt walnut academic agency brave hamster hobo declare herd taste alpha slim criminal mild arcade formal romp branch pink ambition",
      0
    },
    ""
  },
  {
    "14. Insufficient number of groups (128 bits, case 1)",
    {
      "eraser senior beard romp adorn nuclear spill corner cradle style ancient family general leader ambition exchange unusual garlic promise voice",
      0
    },
    ""
  },
  {
    "15. Insufficient number of groups (128 bits, case 2)",
    {
      "eraser senior decision scared cargo theory device idea deliver modify curly include pancake both news skin realize vitamins away join",
      "eraser senior decision roster beard treat identify grumpy salt index fake aviation theater cubic bike cause research dragon emphasis counter",
      0
    },
    ""
  },
  {
    "16. Threshold number of groups, but insufficient number of members in one group (128 bits)",
    {
      "eraser senior decision shadow artist work morning estate greatest pipeline plan ting petition forget hormone flexible general goat admit surface",
      "eraser senior beard romp adorn nuclear spill corner cradle style ancient family general leader ambition exchange unusual garlic promise voice",
      0
    },
    ""
  },
  {
    "17. Threshold number of groups and members in each group (128 bits, case 1)",
    {
      "eraser senior decision roster beard treat identify grumpy salt index fake aviation theater cubic bike cause research dragon emphasis counter",
      "eraser senior ceramic snake clay various huge numb argue hesitate auction category timber browser greatest hanger petition script leaf pickup",
      "eraser senior ceramic shaft dynamic become junior wrist silver peasant force math alto coal amazing segment yelp velvet image paces",
      "eraser senior ceramic round column hawk trust auction smug shame alive greatest sheriff living perfect corner chest sled fumes adequate",
      "eraser senior decision smug corner ruin rescue cubic angel tackle skin skunk program roster trash rumor slush angel flea amazing",
      0
    },
    "7c3397a292a5941682d7a4ae2d898d11"
  },
  {
    "18. Threshold number of groups and members in each group (128 bits, case 2)",
    {
      "eraser senior decision smug corner ruin rescue cubic angel tackle skin skunk program roster trash rumor slush angel flea amazing",
      "eraser senior beard romp adorn nuclear spill corner cradle style ancient family general leader ambition exchange unusual garlic promise voice",
      "eraser senior decision scared cargo theory device idea deliver modify curly include pancake both news skin realize vitamins away join",
      0
    },
    "7c3397a292a5941682d7a4ae2d898d11"
  },
  {
    "19. Threshold number of groups and members in each group (128 bits, case 3)",
    {
      "eraser senior beard romp adorn nuclear spill corner cradle style ancient family general leader ambition exchange unusual garlic promise voice",
      "eraser senior acrobat romp bishop medical gesture pumps secret alive ultimate quarter priest subject class dictate spew material endless market",
      0
    },
    "7c3397a292a5941682d7a4ae2d898d11"
  },
  {
    "20. Valid mnemonic without sharing (256 bits)",
    {
      "theory painting academic academic armed sweater year military elder discuss acne wildlife boring employer fused large satoshi bundle carbon diagnose anatomy hamster leaves tracks paces beyond phantom capital marvel lips brave detect luck",
      0
    },
    "989baf9dcaad5b10ca33dfd8cc75e42477025dce88ae83e75a230086a0e00e92"
  },
  {
    "21. Mnemonic with invalid checksum (256 bits)",
    {
      "theory painting academic academic armed sweater year military elder discuss acne wildlife boring employer fused large satoshi bundle carbon diagnose anatomy hamster leaves tracks paces beyond phantom capital marvel lips brave detect lunar",
      0
    },
    ""
  },
  {
    "22. Mnemonic with invalid padding (256 bits)",
    {
      "theory painting academic academic campus sweater year military elder discuss acne wildlife boring employer fused large satoshi bundle carbon diagnose anatomy hamster leaves tracks paces beyond phantom capital marvel lips facility obtain sister",
      0
    },
    ""
  },
  {
    "23. Basic sharing 2-of-3 (256 bits)",
    {
      "humidity disease academic always aluminum jewelry energy woman receiver strategy amuse duckling lying evidence network walnut tactics forget hairy rebound impulse brother survive clothes stadium mailman rival ocean reward venture always armed unwrap",
      "humidity disease academic agency actress jacket gross physics cylinder solution fake mortgage benefit public busy prepare sharp friar change work slow purchase ruler again tricycle involve viral wireless mixture anatomy desert cargo upgrade",
      0
    },
    "c938b319067687e990e05e0da0ecce1278f75ff58d9853f19dcaeed5de104aae"
  },
  {
    "24. Basic sharing 2-of-3 (256 bits)",
    {
      "humidity disease academic always aluminum jewelry energy woman receiver strategy amuse duckling lying evidence network walnut tactics forget hairy rebound impulse brother survive clothes stadium mailman rival ocean reward venture always armed unwrap",
      0
    },
    ""
  },
  {
    "25. Mnemonics with different identifiers (256 bits)",
    {
      "smear husband academic acid deadline scene venture distance dive overall parking bracelet elevator justice echo burning oven chest duke nylon",
      "smear isolate academic agency alpha mandate decorate burden recover guard exercise fatal force syndrome fumes thank guest drift dramatic mule",
      0
    },
    ""
  },
  {
    "26. Mnemonics with different iteration exponents (256 bits)",
    {
      "finger trash academic acid average priority dish revenue academic hospital spirit western ocean fact calcium syndrome greatest plan losing dictate",
      "finger traffic academic agency building lilac deny paces subject threaten diploma eclipse window unknown health slim piece dragon focus smirk",
      0
    },
    ""
  },
  {
    "27. Mnemonics with mismatching group thresholds (256 bits)",
    {
      "flavor pink beard echo depart forbid retreat become frost helpful juice unwrap reunion credit math burning spine black capital lair",
      "flavor pink beard email diet teaspoon freshman identify document rebound cricket prune headset loyalty smell emission skin often square rebound",
      "flavor pink academic easy credit cage raisin crazy closet lobe mobile become drink human tactics valuable hand capture sympathy finger",
      0
    },
    ""
  },
  {
    "28. Mnemonics with mismatching group counts (256 bits)",
    {
      "column flea academic leaf debut extra surface slow timber husky lawsuit game behavior husky swimming already paper episode tricycle scroll",
      "column flea academic agency blessing garbage party software stadium verify silent umbrella therapy decorate chemical erode dramatic eclipse replace apart",
      0
    },
    ""
  },
  {
    "29. Mnemonics with greater group threshold than group counts (256 bits)",
    {
      "smirk pink acrobat acid auction wireless impulse spine sprinkle fortune clogs elbow guest hush loyalty crush dictate tracks airport talent",
      "smirk pink acrobat agency dwarf emperor ajar organize legs slice harvest plastic dynamic style mobile float bulb health coding credit",
      "smirk pink beard academic alto strategy carve shame language rapids ruin smart location spray training acquire eraser endorse submit peaceful",
      0
    },
    ""
  },
  {
    "30. Mnemonics with duplicate member indices (256 bits)",
    {
      "fishing recover academic always device craft trend snapshot gums skin downtown watch device sniff hour clock public maximum garlic born",
      "fishing recover academic always aircraft view software cradle fangs amazing package plastic evaluate intend penalty epidemic anatomy quarter cage apart",
      0
    },
    ""
  },
  {
    "31. Mnemonics with mismatching member thresholds (256 bits)",
    {
      "evoke garden academic academic answer wolf scandal modern warmth station devote emerald market physics surface formal amazing aquatic gesture medical",
      "evoke garden academic agency deal revenue knit reunion decrease magazine flexible company goat repair alarm military facility clogs aide mandate",
      0
    },
    ""
  },
  {
    "32. Mnemonics giving an invalid digest (256 bits)",
    {
      "river deal academic acid average forbid pistol peanut custody bike class aunt hairy merit valid flexible learn ajar very easel",
      "river deal academic agency camera amuse lungs numb isolate display smear piece traffic worthy year patrol crush fact fancy emission",
      0
    },
    ""
  },
  {
    "33. Insufficient number of groups (256 bits, case 1)",
    {
      "wildlife deal beard romp alcohol space mild usual clothes union nuclear testify course research heat listen task location thank hospital slice smell failure fawn helpful priest ambition average recover lecture process dough stadium",
      0
    },
    ""
  },
  {
    "34. Insufficient number of groups (256 bits, case 2)",
    {
      "wildlife deal decision scared acne fatal snake paces obtain election dryer dominant romp tactics railroad marvel trust helpful flip peanut theory theater photo luck install entrance taxi step oven network dictate intimate listen",
      "wildlife deal decision smug ancestor genuine move huge cubic strategy smell game costume extend swimming false desire fake traffic vegan senior twice timber submit leader payroll fraction apart exact forward pulse tidy install",
      0
    },
    ""
  },
  {
    "35. Threshold number of groups, but insufficient number of members in one group (256 bits)",
    {
      "wildlife deal decision shadow analysis adjust bulb skunk muscle mandate obesity total guitar coal gravity carve slim jacket ruin rebuild ancestor numerous hour mortgage require herd maiden public ceiling pecan pickup shadow club",
      "wildlife deal beard romp alcohol space mild usual clothes union nuclear testify course research heat listen task location thank hospital slice smell failure fawn helpful priest ambition average recover lecture process dough stadium",
      0
    },
    ""
  },
  {
    "36. Threshold number of groups and members in each group (256 bits, case 1)",
    {
      "wildlife deal ceramic round aluminum pitch goat racism employer miracle percent math decision episode dramatic editor lily prospect program scene rebuild display sympathy have single mustang junction relate often chemical society wits estate",
      "wildlife deal decision scared acne fatal snake paces obtain election dryer dominant romp tactics railroad marvel trust helpful flip peanut theory theater photo luck install entrance taxi step oven network dictate intimate listen",
      "wildlife deal ceramic scatter argue equip vampire together ruin reject literary rival distance aquatic agency teammate rebound false argue miracle stay again blessing peaceful unknown cover beard acid island language debris industry idle",
      "wildlife deal ceramic snake agree voter main lecture axis kitchen physics arcade velvet spine idea scroll promise platform firm sharp patrol divorce ancestor fantasy forbid goat ajar believe swimming cowboy symbolic plastic spelling",
      "wildlife deal decision shadow analysis adjust bulb skunk muscle mandate obesity total guitar coal gravity carve slim jacket ruin rebuild ancestor numerous hour mortgage require herd maiden public ceiling pecan pickup shadow club",
      0
    },
    "5385577c8cfc6c1a8aa0f7f10ecde0a3318493262591e78b8c14c6686167123b"
  },
  {
    "37. Threshold number of groups and members in each group (256 bits, case 2)",
    {
      "wildlife deal decision scared acne fatal snake paces obtain election dryer dominant romp tactics railroad marvel trust helpful flip peanut theory theater photo luck install entrance taxi step oven network dictate intimate listen",
      "wildlife deal beard romp alcohol space mild usual clothes union nuclear testify course research heat listen task location thank hospital slice smell failure fawn helpful priest ambition average recover lecture process dough stadium",
      "wildlife deal decision smug ancestor genuine move huge cubic strategy smell game costume extend swimming false desire fake traffic vegan senior twice timber submit leader payroll fraction apart exact forward pulse tidy install",
      0
    },
    "5385577c8cfc6c1a8aa0f7f10ecde0a3318493262591e78b8c14c6686167123b"
  },
  {
    "38. Threshold number of groups and members in each group (256 bits, case 3)",
    {
      "wildlife deal beard romp alcohol space mild usual clothes union nuclear testify course research heat listen task location thank hospital slice smell failure fawn helpful priest ambition average recover lecture process dough stadium",
      "wildlife deal acrobat romp anxiety axis starting require metric flexible geology game drove editor edge screw helpful have huge holy making pitch unknown carve holiday numb glasses survive already tenant adapt goat fangs",
      0
    },
    "5385577c8cfc6c1a8aa0f7f10ecde0a3318493262591e78b8c14c6686167123b"
  },
  {
    "39. Mnemonic with insufficient length",
    {
      "junk necklace academic academic acne isolate join hesitate lunar roster dough calcium chemical ladybug amount mobile glasses verify cylinder",
      0
    },
    ""
  },
  {
    "40. Mnemonic with invalid master secret length",
    {
      "fraction necklace academic academic award teammate mouse regular testify coding building member verdict purchase blind camera duration email prepare spirit quarter",
      0
    },
    ""
  }
};


int fromhex(uint8_t *buf, uint32_t *buf_len, const char *str);
void dumphex(uint8_t *b, int l);


int test_vectors(void)
{

    int i, gn, sl;
    char **ml;
    char pass[] = "TREZOR";
    uint8_t ms[32];
    int msl;
    uint8_t vs[32];
    int vsl;
    int ret;


    for (i = 0; i < 40; i++)
    {
        ml = vectors[i].mnemonic;

        gn = 0;
        while (ml[gn] != 0)
            gn++;

        printf("%s\n", vectors[i].description);
        sl = strlen(vectors[i].secret);
        msl = sizeof(ms);
        ret = combine_mnemonics(gn ,ml, pass, strlen(pass), ms, &msl);

        if (ret == 0)
        {
            vsl = sizeof(vs);
            fromhex(vs, &vsl, vectors[i].secret);

            if (vsl == msl)
            {
                if (memcmp(ms, vs, msl) == 0)
                    printf("--> PASS\n");
                else
                {
                    printf("--> FAIL <--------\n");
                }
            }
            else
            {
                printf("--> FAIL <--------\n");
            }
        }
        else
        {
            if (strlen(vectors[i].secret) == 0)
                printf("--> PASS\n");
            else
                printf("--> FAIL <--------\n");
        }
    }
}

