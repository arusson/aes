#include <stdint.h>
#include "aes.h"

/* precomputed tables that merge SB and MC */
const word32 table0[256] = {
  3328402341, 4168907908, 4000806809, 4135287693, 4294111757, 3597364157, 3731845041, 2445657428,
  1613770832,   33620227, 3462883241, 1445669757, 3892248089, 3050821474, 1303096294, 3967186586,
  2412431941,  528646813, 2311702848, 4202528135, 4026202645, 2992200171, 2387036105, 4226871307,
  1101901292, 3017069671, 1604494077, 1169141738,  597466303, 1403299063, 3832705686, 2613100635,
  1974974402, 3791519004, 1033081774, 1277568618, 1815492186, 2118074177, 4126668546, 2211236943,
  1748251740, 1369810420, 3521504564, 4193382664, 3799085459, 2883115123, 1647391059,  706024767,
  134480908,  2512897874, 1176707941, 2646852446,  806885416,  932615841,  168101135,  798661301,
  235341577,   605164086,  461406363, 3756188221, 3454790438, 1311188841, 2142417613, 3933566367,
  302582043,   495158174, 1479289972,  874125870,  907746093, 3698224818, 3025820398, 1537253627,
  2756858614, 1983593293, 3084310113, 2108928974, 1378429307, 3722699582, 1580150641,  327451799,
  2790478837, 3117535592,          0, 3253595436, 1075847264, 3825007647, 2041688520, 3059440621,
  3563743934, 2378943302, 1740553945, 1916352843, 2487896798, 2555137236, 2958579944, 2244988746,
  3151024235, 3320835882, 1336584933, 3992714006, 2252555205, 2588757463, 1714631509,  293963156,
  2319795663, 3925473552,   67240454, 4269768577, 2689618160, 2017213508,  631218106, 1269344483,
  2723238387, 1571005438, 2151694528,   93294474, 1066570413,  563977660, 1882732616, 4059428100,
  1673313503, 2008463041, 2950355573, 1109467491,  537923632, 3858759450, 4260623118, 3218264685,
  2177748300,  403442708,  638784309, 3287084079, 3193921505,  899127202, 2286175436,  773265209,
  2479146071, 1437050866, 4236148354, 2050833735, 3362022572, 3126681063,  840505643, 3866325909,
  3227541664,  427917720, 2655997905, 2749160575, 1143087718, 1412049534,  999329963,  193497219,
  2353415882, 3354324521, 1807268051,  672404540, 2816401017, 3160301282,  369822493, 2916866934,
  3688947771, 1681011286, 1949973070,  336202270, 2454276571,  201721354, 1210328172, 3093060836,
  2680341085, 3184776046, 1135389935, 3294782118,  965841320,  831886756, 3554993207, 4068047243,
  3588745010, 2345191491, 1849112409, 3664604599,   26054028, 2983581028, 2622377682, 1235855840,
  3630984372, 2891339514, 4092916743, 3488279077, 3395642799, 4101667470, 1202630377,  268961816,
  1874508501, 4034427016, 1243948399, 1546530418,  941366308, 1470539505, 1941222599, 2546386513,
  3421038627, 2715671932, 3899946140, 1042226977, 2521517021, 1639824860,  227249030,  260737669,
  3765465232, 2084453954, 1907733956, 3429263018, 2420656344,  100860677, 4160157185,  470683154,
  3261161891, 1781871967, 2924959737, 1773779408,  394692241, 2579611992,  974986535,  664706745,
  3655459128, 3958962195,  731420851,  571543859, 3530123707, 2849626480,  126783113,  865375399,
  765172662,  1008606754,  361203602, 3387549984, 2278477385, 2857719295, 1344809080, 2782912378,
  59542671,   1503764984,  160008576,  437062935, 1707065306, 3622233649, 2218934982, 3496503480,
  2185314755,  697932208, 1512910199,  504303377, 2075177163, 2824099068, 1841019862,  739644986};

const word32 table1[256] = {
  2781242211, 2230877308, 2582542199, 2381740923,  234877682, 3184946027, 2984144751, 1418839493,
  1348481072,   50462977, 2848876391, 2102799147,  434634494, 1656084439, 3863849899, 2599188086,
  1167051466, 2636087938, 1082771913, 2281340285,  368048890, 3954334041, 3381544775,  201060592,
  3963727277, 1739838676, 4250903202, 3930435503, 3206782108, 4149453988, 2531553906, 1536934080,
  3262494647,  484572669, 2923271059, 1783375398, 1517041206, 1098792767,   49674231, 1334037708,
  1550332980, 4098991525,  886171109,  150598129, 2481090929, 1940642008, 1398944049, 1059722517,
  201851908,  1385547719, 1699095331, 1587397571,  674240536, 2704774806,  252314885, 3039795866,
  151914247,   908333586, 2602270848, 1038082786,  651029483, 1766729511, 3447698098, 2682942837,
  454166793,  2652734339, 1951935532,  775166490,  758520603, 3000790638, 4004797018, 4217086112,
  4137964114, 1299594043, 1639438038, 3464344499, 2068982057, 1054729187, 1901997871, 2534638724,
  4121318227, 1757008337,          0,  750906861, 1614815264,  535035132, 3363418545, 3988151131,
  3201591914, 1183697867, 3647454910, 1265776953, 3734260298, 3566750796, 3903871064, 1250283471,
  1807470800,  717615087, 3847203498,  384695291, 3313910595, 3617213773, 1432761139, 2484176261,
  3481945413,  283769337,  100925954, 2180939647, 4037038160, 1148730428, 3123027871, 3813386408,
  4087501137, 4267549603, 3229630528, 2315620239, 2906624658, 3156319645, 1215313976,   82966005,
  3747855548, 3245848246, 1974459098, 1665278241,  807407632,  451280895,  251524083, 1841287890,
  1283575245,  337120268,  891687699,  801369324, 3787349855, 2721421207, 3431482436,  959321879,
  1469301956, 4065699751, 2197585534, 1199193405, 2898814052, 3887750493,  724703513, 2514908019,
  2696962144, 2551808385, 3516813135, 2141445340, 1715741218, 2119445034, 2872807568, 2198571144,
  3398190662,  700968686, 3547052216, 1009259540, 2041044702, 3803995742,  487983883, 1991105499,
  1004265696, 1449407026, 1316239930,  504629770, 3683797321,  168560134, 1816667172, 3837287516,
  1570751170, 1857934291, 4014189740, 2797888098, 2822345105, 2754712981,  936633572, 2347923833,
  852879335,  1133234376, 1500395319, 3084545389, 2348912013, 1689376213, 3533459022, 3762923945,
  3034082412, 4205598294,  133428468,  634383082, 2949277029, 2398386810, 3913789102,  403703816,
  3580869306, 2297460856, 1867130149, 1918643758,  607656988, 4049053350, 3346248884, 1368901318,
  600565992,  2090982877, 2632479860,  557719327, 3717614411, 3697393085, 2249034635, 2232388234,
  2430627952, 1115438654, 3295786421, 2865522278, 3633334344,   84280067,   33027830,  303828494,
  2747425121, 1600795957, 4188952407, 3496589753, 2434238086, 1486471617,  658119965, 3106381470,
  953803233,   334231800, 3005978776,  857870609, 3151128937, 1890179545, 2298973838, 2805175444,
  3056442267,  574365214, 2450884487,  550103529, 1233637070, 4289353045, 2018519080, 2057691103,
  2399374476, 4166623649, 2148108681,  387583245, 3664101311,  836232934, 3330556482, 3100665960,
  3280093505, 2955516313, 2002398509,  287182607, 3413881008, 4238890068, 3597515707,  975967766};

const word32 table2[256] = {
  1671808611, 2089089148, 2006576759, 2072901243, 4061003762, 1807603307, 1873927791, 3310653893,
  810573872,    16974337, 1739181671,  729634347, 4263110654, 3613570519, 2883997099, 1989864566,
  3393556426, 2191335298, 3376449993, 2106063485, 4195741690, 1508618841, 1204391495, 4027317232,
  2917941677, 3563566036, 2734514082, 2951366063, 2629772188, 2767672228, 1922491506, 3227229120,
  3082974647, 4246528509, 2477669779,  644500518,  911895606, 1061256767, 4144166391, 3427763148,
  878471220,  2784252325, 3845444069, 4043897329, 1905517169, 3631459288,  827548209,  356461077,
  67897348,   3344078279,  593839651, 3277757891,  405286936, 2527147926,   84871685, 2595565466,
  118033927,   305538066, 2157648768, 3795705826, 3945188843,  661212711, 2999812018, 1973414517,
  152769033,  2208177539,  745822252,  439235610,  455947803, 1857215598, 1525593178, 2700827552,
  1391895634,  994932283, 3596728278, 3016654259,  695947817, 3812548067,  795958831, 2224493444,
  1408607827, 3513301457,          0, 3979133421,  543178784, 4229948412, 2982705585, 1542305371,
  1790891114, 3410398667, 3201918910,  961245753, 1256100938, 1289001036, 1491644504, 3477767631,
  3496721360, 4012557807, 2867154858, 4212583931, 1137018435, 1305975373,  861234739, 2241073541,
  1171229253, 4178635257,   33948674, 2139225727, 1357946960, 1011120188, 2679776671, 2833468328,
  1374921297, 2751356323, 1086357568, 2408187279, 2460827538, 2646352285,  944271416, 4110742005,
  3168756668, 3066132406, 3665145818,  560153121,  271589392, 4279952895, 4077846003, 3530407890,
  3444343245,  202643468,  322250259, 3962553324, 1608629855, 2543990167, 1154254916,  389623319,
  3294073796, 2817676711, 2122513534, 1028094525, 1689045092, 1575467613,  422261273, 1939203699,
  1621147744, 2174228865, 1339137615, 3699352540,  577127458,  712922154, 2427141008, 2290289544,
  1187679302, 3995715566, 3100863416,  339486740, 3732514782, 1591917662,  186455563, 3681988059,
  3762019296,  844522546,  978220090,  169743370, 1239126601,  101321734,  611076132, 1558493276,
  3260915650, 3547250131, 2901361580, 1655096418, 2443721105, 2510565781, 3828863972, 2039214713,
  3878868455, 3359869896,  928607799, 1840765549, 2374762893, 3580146133, 1322425422, 2850048425,
  1823791212, 1459268694, 4094161908, 3928346602, 1706019429, 2056189050, 2934523822,  135794696,
  3134549946, 2022240376,  628050469,  779246638,  472135708, 2800834470, 3032970164, 3327236038,
  3894660072, 3715932637, 1956440180,  522272287, 1272813131, 3185336765, 2340818315, 2323976074,
  1888542832, 1044544574, 3049550261, 1722469478, 1222152264,   50660867, 4127324150,  236067854,
  1638122081,  895445557, 1475980887, 3117443513, 2257655686, 3243809217,  489110045, 2662934430,
  3778599393, 4162055160, 2561878936,  288563729, 1773916777, 3648039385, 2391345038, 2493985684,
  2612407707,  505560094, 2274497927, 3911240169, 3460925390, 1442818645,  678973480, 3749357023,
  2358182796, 2717407649, 2306869641,  219617805, 3218761151, 3862026214, 1120306242, 1756942440,
  1103331905, 2578459033,  762796589,  252780047, 2966125488, 1425844308, 3151392187,  372911126};

const word32 table3[256] = {
  1667474886, 2088535288, 2004326894, 2071694838, 4075949567, 1802223062, 1869591006, 3318043793,
  808472672,    16843522, 1734846926,  724270422, 4278065639, 3621216949, 2880169549, 1987484396,
  3402253711, 2189597983, 3385409673, 2105378810, 4210693615, 1499065266, 1195886990, 4042263547,
  2913856577, 3570689971, 2728590687, 2947541573, 2627518243, 2762274643, 1920112356, 3233831835,
  3082273397, 4261223649, 2475929149,  640051788,  909531756, 1061110142, 4160160501, 3435941763,
  875846760,  2779116625, 3857003729, 4059105529, 1903268834, 3638064043,  825316194,  353713962,
  67374088,   3351728789,  589522246, 3284360861,  404236336, 2526454071,   84217610, 2593830191,
  117901582,   303183396, 2155911963, 3806477791, 3958056653,  656894286, 2998062463, 1970642922,
  151591698,  2206440989,  741110872,  437923380,  454765878, 1852748508, 1515908788, 2694904667,
  1381168804,  993742198, 3604373943, 3014905469,  690584402, 3823320797,  791638366, 2223281939,
  1398011302, 3520161977,          0, 3991743681,  538992704, 4244381667, 2981218425, 1532751286,
  1785380564, 3419096717, 3200178535,  960056178, 1246420628, 1280103576, 1482221744, 3486468741,
  3503319995, 4025428677, 2863326543, 4227536621, 1128514950, 1296947098,  859002214, 2240123921,
  1162203018, 4193849577,   33687044, 2139062782, 1347481760, 1010582648, 2678045221, 2829640523,
  1364325282, 2745433693, 1077985408, 2408548869, 2459086143, 2644360225,  943212656, 4126475505,
  3166494563, 3065430391, 3671750063,  555836226,  269496352, 4294908645, 4092792573, 3537006015,
  3452783745,  202118168,  320025894, 3974901699, 1600119230, 2543297077, 1145359496,  387397934,
  3301201811, 2812801621, 2122220284, 1027426170, 1684319432, 1566435258,  421079858, 1936954854,
  1616945344, 2172753945, 1330631070, 3705438115,  572679748,  707427924, 2425400123, 2290647819,
  1179044492, 4008585671, 3099120491,  336870440, 3739122087, 1583276732,  185277718, 3688593069,
  3772791771,  842159716,  976899700,  168435220, 1229577106,  101059084,  606366792, 1549591736,
  3267517855, 3553849021, 2897014595, 1650632388, 2442242105, 2509612081, 3840161747, 2038008818,
  3890688725, 3368567691,  926374254, 1835907034, 2374863873, 3587531953, 1313788572, 2846482505,
  1819063512, 1448540844, 4109633523, 3941213647, 1701162954, 2054852340, 2930698567,  134748176,
  3132806511, 2021165296,  623210314,  774795868,  471606328, 2795958615, 3031746419, 3334885783,
  3907527627, 3722280097, 1953799400,  522133822, 1263263126, 3183336545, 2341176845, 2324333839,
  1886425312, 1044267644, 3048588401, 1718004428, 1212733584,   50529542, 4143317495,  235803164,
  1633788866,  892690282, 1465383342, 3115962473, 2256965911, 3250673817,  488449850, 2661202215,
  3789633753, 4177007595, 2560144171,  286339874, 1768537042, 3654906025, 2391705863, 2492770099,
  2610673197,  505291324, 2273808917, 3924369609, 3469625735, 1431699370,  673740880, 3755965093,
  2358021891, 2711746649, 2307489801,  218961690, 3217021541, 3873845719, 1111672452, 1751693520,
  1094828930, 2576986153,  757954394,  252645662, 2964376443, 1414855848, 3149649517,  370555436};

const word32 itable0[256] = {
  1374988112, 2118214995,  437757123,  975658646, 1001089995,  530400753, 2902087851, 1273168787,
  540080725,  2910219766, 2295101073, 4110568485, 1340463100, 3307916247,  641025152, 3043140495,
  3736164937,  632953703, 1172967064, 1576976609, 3274667266, 2169303058, 2370213795, 1809054150,
  59727847,    361929877, 3211623147, 2505202138, 3569255213, 1484005843, 1239443753, 2395588676,
  1975683434, 4102977912, 2572697195,  666464733, 3202437046, 4035489047, 3374361702, 2110667444,
  1675577880, 3843699074, 2538681184, 1649639237, 2976151520, 3144396420, 4269907996, 4178062228,
  1883793496, 2403728665, 2497604743, 1383856311, 2876494627, 1917518562, 3810496343, 1716890410,
  3001755655,  800440835, 2261089178, 3543599269,  807962610,  599762354,   33778362, 3977675356,
  2328828971, 2809771154, 4077384432, 1315562145, 1708848333,  101039829, 3509871135, 3299278474,
  875451293,  2733856160,   92987698, 2767645557,  193195065, 1080094634, 1584504582, 3178106961,
  1042385657, 2531067453, 3711829422, 1306967366, 2438237621, 1908694277,   67556463, 1615861247,
  429456164,  3602770327, 2302690252, 1742315127, 2968011453,  126454664, 3877198648, 2043211483,
  2709260871, 2084704233, 4169408201,          0,  159417987,  841739592,  504459436, 1817866830,
  4245618683,  260388950, 1034867998,  908933415,  168810852, 1750902305, 2606453969,  607530554,
  202008497,  2472011535, 3035535058,  463180190, 2160117071, 1641816226, 1517767529,  470948374,
  3801332234, 3231722213, 1008918595,  303765277,  235474187, 4069246893,  766945465,  337553864,
  1475418501, 2943682380, 4003061179, 2743034109, 4144047775, 1551037884, 1147550661, 1543208500,
  2336434550, 3408119516, 3069049960, 3102011747, 3610369226, 1113818384,  328671808, 2227573024,
  2236228733, 3535486456, 2935566865, 3341394285,  496906059, 3702665459,  226906860, 2009195472,
  733156972,  2842737049,  294930682, 1206477858, 2835123396, 2700099354, 1451044056,  573804783,
  2269728455, 3644379585, 2362090238, 2564033334, 2801107407, 2776292904, 3669462566, 1068351396,
  742039012,  1350078989, 1784663195, 1417561698, 4136440770, 2430122216,  775550814, 2193862645,
  2673705150, 1775276924, 1876241833, 3475313331, 3366754619,  270040487, 3902563182, 3678124923,
  3441850377, 1851332852, 3969562369, 2203032232, 3868552805, 2868897406,  566021896, 4011190502,
  3135740889, 1248802510, 3936291284,  699432150,  832877231,  708780849, 3332740144,  899835584,
  1951317047, 4236429990, 3767586992,  866637845, 4043610186, 1106041591, 2144161806,  395441711,
  1984812685, 1139781709, 3433712980, 3835036895, 2664543715, 1282050075, 3240894392, 1181045119,
  2640243204,   25965917, 4203181171, 4211818798, 3009879386, 2463879762, 3910161971, 1842759443,
  2597806476,  933301370, 1509430414, 3943906441, 3467192302, 3076639029, 3776767469, 2051518780,
  2631065433, 1441952575,  404016761, 1942435775, 1408749034, 1610459739, 3745345300, 2017778566,
  3400528769, 3110650942,  941896748, 3265478751,  371049330, 3168937228,  675039627, 4279080257,
  967311729,   135050206, 3635733660, 1683407248, 2076935265, 3576870512, 1215061108, 3501741890};

const word32 itable1[256] = {
  1347548327, 1400783205, 3273267108, 2520393566, 3409685355, 4045380933, 2880240216, 2471224067,
  1428173050, 4138563181, 2441661558,  636813900, 4233094615, 3620022987, 2149987652, 2411029155,
  1239331162, 1730525723, 2554718734, 3781033664,   46346101,  310463728, 2743944855, 3328955385,
  3875770207, 2501218972, 3955191162, 3667219033,  768917123, 3545789473,  692707433, 1150208456,
  1786102409, 2029293177, 1805211710, 3710368113, 3065962831,  401639597, 1724457132, 3028143674,
  409198410,  2196052529, 1620529459, 1164071807, 3769721975, 2226875310,  486441376, 2499348523,
  1483753576,  428819965, 2274680428, 3075636216,  598438867, 3799141122, 1474502543,  711349675,
  129166120,    53458370, 2592523643, 2782082824, 4063242375, 2988687269, 3120694122, 1559041666,
  730517276,  2460449204, 4042459122, 2706270690, 3446004468, 3573941694,  533804130, 2328143614,
  2637442643, 2695033685,  839224033, 1973745387,  957055980, 2856345839,  106852767, 1371368976,
  4181598602, 1033297158, 2933734917, 1179510461, 3046200461,   91341917, 1862534868, 4284502037,
  605657339,  2547432937, 3431546947, 2003294622, 3182487618, 2282195339,  954669403, 3682191598,
  1201765386, 3917234703, 3388507166,          0, 2198438022, 1211247597, 2887651696, 1315723890,
  4227665663, 1443857720,  507358933,  657861945, 1678381017,  560487590, 3516619604,  975451694,
  2970356327,  261314535, 3535072918, 2652609425, 1333838021, 2724322336, 1767536459,  370938394,
  182621114,  3854606378, 1128014560,  487725847,  185469197, 2918353863, 3106780840, 3356761769,
  2237133081, 1286567175, 3152976349, 4255350624, 2683765030, 3160175349, 3309594171,  878443390,
  1988838185, 3704300486, 1756818940, 1673061617, 3403100636,  272786309, 1075025698,  545572369,
  2105887268, 4174560061,  296679730, 1841768865, 1260232239, 4091327024, 3960309330, 3497509347,
  1814803222, 2578018489, 4195456072,  575138148, 3299409036,  446754879, 3629546796, 4011996048,
  3347532110, 3252238545, 4270639778,  915985419, 3483825537,  681933534,  651868046, 2755636671,
  3828103837,  223377554, 2607439820, 1649704518, 3270937875, 3901806776, 1580087799, 4118987695,
  3198115200, 2087309459, 2842678573, 3016697106, 1003007129, 2802849917, 1860738147, 2077965243,
  164439672,  4100872472,   32283319, 2827177882, 1709610350, 2125135846,  136428751, 3874428392,
  3652904859, 3460984630, 3572145929, 3593056380, 2939266226,  824852259,  818324884, 3224740454,
  930369212,  2801566410, 2967507152,  355706840, 1257309336, 4148292826,  243256656,  790073846,
  2373340630, 1296297904, 1422699085, 3756299780, 3818836405,  457992840, 3099667487, 2135319889,
  77422314,   1560382517, 1945798516,  788204353, 1521706781, 1385356242,  870912086,  325965383,
  2358957921, 2050466060, 2388260884, 2313884476, 4006521127,  901210569, 3990953189, 1014646705,
  1503449823, 1062597235, 2031621326, 3212035895, 3931371469, 1533017514,  350174575, 2256028891,
  2177544179, 1052338372,  741876788, 1606591296, 1914052035,  213705253, 2334669897, 1107234197,
  1899603969, 3725069491, 2631447780, 2422494913, 1635502980, 1893020342, 1950903388, 1120974935};

const word32 itable2[256] = {
  2807058932, 1699970625, 2764249623, 1586903591, 1808481195, 1173430173, 1487645946,   59984867,
  4199882800, 1844882806, 1989249228, 1277555970, 3623636965, 3419915562, 1149249077, 2744104290,
  1514790577,  459744698,  244860394, 3235995134, 1963115311, 4027744588, 2544078150, 4190530515,
  1608975247, 2627016082, 2062270317, 1507497298, 2200818878,  567498868, 1764313568, 3359936201,
  2305455554, 2037970062, 1047239000, 1910319033, 1337376481, 2904027272, 2892417312,  984907214,
  1243112415,  830661914,  861968209, 2135253587, 2011214180, 2927934315, 2686254721,  731183368,
  1750626376, 4246310725, 1820824798, 4172763771, 3542330227,   48394827, 2404901663, 2871682645,
  671593195,  3254988725, 2073724613,  145085239, 2280796200, 2779915199, 1790575107, 2187128086,
  472615631,  3029510009, 4075877127, 3802222185, 4107101658, 3201631749, 1646252340, 4270507174,
  1402811438, 1436590835, 3778151818, 3950355702, 3963161475, 4020912224, 2667994737,  273792366,
  2331590177,  104699613,   95345982, 3175501286, 2377486676, 1560637892, 3564045318,  369057872,
  4213447064, 3919042237, 1137477952, 2658625497, 1119727848, 2340947849, 1530455833, 4007360968,
  172466556,   266959938,  516552836,          0, 2256734592, 3980931627, 1890328081, 1917742170,
  4294704398,  945164165, 3575528878,  958871085, 3647212047, 2787207260, 1423022939,  775562294,
  1739656202, 3876557655, 2530391278, 2443058075, 3310321856,  547512796, 1265195639,  437656594,
  3121275539,  719700128, 3762502690,  387781147,  218828297, 3350065803, 2830708150, 2848461854,
  428169201,   122466165, 3720081049, 1627235199,  648017665, 4122762354, 1002783846, 2117360635,
  695634755,  3336358691, 4234721005, 4049844452, 3704280881, 2232435299,  574624663,  287343814,
  612205898,  1039717051,  840019705, 2708326185,  793451934,  821288114, 1391201670, 3822090177,
  376187827,  3113855344, 1224348052, 1679968233, 2361698556, 1058709744,  752375421, 2431590963,
  1321699145, 3519142200, 2734591178,  188127444, 2177869557, 3727205754, 2384911031, 3215212461,
  2648976442, 2450346104, 3432737375, 1180849278,  331544205, 3102249176, 4150144569, 2952102595,
  2159976285, 2474404304,  766078933,  313773861, 2570832044, 2108100632, 1668212892, 3145456443,
  2013908262,  418672217, 3070356634, 2594734927, 1852171925, 3867060991, 3473416636, 3907448597,
  2614737639,  919489135,  164948639, 2094410160, 2997825956,  590424639, 2486224549, 1723872674,
  3157750862, 3399941250, 3501252752, 3625268135, 2555048196, 3673637356, 1343127501, 4130281361,
  3599595085, 2957853679, 1297403050,   81781910, 3051593425, 2283490410,  532201772, 1367295589,
  3926170974,  895287692, 1953757831, 1093597963,  492483431, 3528626907, 1446242576, 1192455638,
  1636604631,  209336225,  344873464, 1015671571,  669961897, 3375740769, 3857572124, 2973530695,
  3747192018, 1933530610, 3464042516,  935293895, 3454686199, 2858115069, 1863638845, 3683022916,
  4085369519, 3292445032,  875313188, 1080017571, 3279033885,  621591778, 1233856572, 2504130317,
  24197544,   3017672716, 3835484340, 3247465558, 2220981195, 3060847922, 1551124588, 1463996600};

const word32 itable3[256] = {
  4104605777, 1097159550,  396673818,  660510266, 2875968315, 2638606623, 4200115116, 3808662347,
  821712160,  1986918061, 3430322568,   38544885, 3856137295,  718002117,  893681702, 1654886325,
  2975484382, 3122358053, 3926825029, 4274053469,  796197571, 1290801793, 1184342925, 3556361835,
  2405426947, 2459735317, 1836772287, 1381620373, 3196267988, 1948373848, 3764988233, 3385345166,
  3263785589, 2390325492, 1480485785, 3111247143, 3780097726, 2293045232,  548169417, 3459953789,
  3746175075,  439452389, 1362321559, 1400849762, 1685577905, 1806599355, 2174754046,  137073913,
  1214797936, 1174215055, 3731654548, 2079897426, 1943217067, 1258480242,  529487843, 1437280870,
  3945269170, 3049390895, 3313212038,  923313619,  679998000, 3215307299,   57326082,  377642221,
  3474729866, 2041877159,  133361907, 1776460110, 3673476453,   96392454,  878845905, 2801699524,
  777231668,  4082475170, 2330014213, 4142626212, 2213296395, 1626319424, 1906247262, 1846563261,
  562755902,  3708173718, 1040559837, 3871163981, 1418573201, 3294430577,  114585348, 1343618912,
  2566595609, 3186202582, 1078185097, 3651041127, 3896688048, 2307622919,  425408743, 3371096953,
  2081048481, 1108339068, 2216610296,          0, 2156299017,  736970802,  292596766, 1517440620,
  251657213,  2235061775, 2933202493,  758720310,  265905162, 1554391400, 1532285339,  908999204,
  174567692,  1474760595, 4002861748, 2610011675, 3234156416, 3693126241, 2001430874,  303699484,
  2478443234, 2687165888,  585122620,  454499602,  151849742, 2345119218, 3064510765,  514443284,
  4044981591, 1963412655, 2581445614, 2137062819,   19308535, 1928707164, 1715193156, 4219352155,
  1126790795,  600235211, 3992742070, 3841024952,  836553431, 1669664834, 2535604243, 3323011204,
  1243905413, 3141400786, 4180808110,  698445255, 2653899549, 2989552604, 2253581325, 3252932727,
  3004591147, 1891211689, 2487810577, 3915653703, 4237083816, 4030667424, 2100090966,  865136418,
  1229899655,  953270745, 3399679628, 3557504664, 4118925222, 2061379749, 3079546586, 2915017791,
  983426092,  2022837584, 1607244650, 2118541908, 2366882550, 3635996816,  972512814, 3283088770,
  1568718495, 3499326569, 3576539503,  621982671, 2895723464,  410887952, 2623762152, 1002142683,
  645401037,  1494807662, 2595684844, 1335535747, 2507040230, 4293295786, 3167684641,  367585007,
  3885750714, 1865862730, 2668221674, 2960971305, 2763173681, 1059270954, 2777952454, 2724642869,
  1320957812, 2194319100, 2429595872, 2815956275,   77089521, 3973773121, 3444575871, 2448830231,
  1305906550, 4021308739, 2857194700, 2516901860, 3518358430, 1787304780,  740276417, 1699839814,
  1592394909, 2352307457, 2272556026,  188821243, 1729977011, 3687994002,  274084841, 3594982253,
  3613494426, 2701949495, 4162096729,  322734571, 2837966542, 1640576439,  484830689, 1202797690,
  3537852828, 4067639125,  349075736, 3342319475, 4157467219, 4255800159, 1030690015, 1155237496,
  2951971274, 1757691577,  607398968, 2738905026,  499347990, 3794078908, 1011452712,  227885567,
  2818666809,  213114376, 3034881240, 1455525988, 3414450555,  850817237, 1817998408, 3092726480};

const byte invsbox[256]={
  82,    9, 106, 213,  48,  54, 165,  56, 191,  64, 163, 158, 129, 243, 215, 251,
  124, 227,  57, 130, 155,  47, 255, 135,  52, 142,  67,  68, 196, 222, 233, 203,
  84,  123, 148,  50, 166, 194,  35,  61, 238,  76, 149,  11,  66, 250, 195,  78,
  8,    46, 161, 102,  40, 217,  36, 178, 118,  91, 162,  73, 109, 139, 209,  37,
  114, 248, 246, 100, 134, 104, 152,  22, 212, 164,  92, 204,  93, 101, 182, 146,
  108, 112,  72,  80, 253, 237, 185, 218,  94,  21,  70,  87, 167, 141, 157, 132,
  144, 216, 171,   0, 140, 188, 211,  10, 247, 228,  88,   5, 184, 179,  69,   6,
  208,  44,  30, 143, 202,  63,  15,   2, 193, 175, 189,   3,   1,  19, 138, 107,
  58,  145,  17,  65,  79, 103, 220, 234, 151, 242, 207, 206, 240, 180, 230, 115,
  150, 172, 116,  34, 231, 173,  53, 133, 226, 249,  55, 232,  28, 117, 223, 110,
  71,  241,  26, 113,  29,  41, 197, 137, 111, 183,  98,  14, 170,  24, 190,  27,
  252,  86,  62,  75, 198, 210, 121,  32, 154, 219, 192, 254, 120, 205,  90, 244,
  31,  221, 168,  51, 136,   7, 199,  49, 177,  18,  16,  89,  39, 128, 236,  95,
  96,   81, 127, 169,  25, 181,  74,  13,  45, 229, 122, 159, 147, 201, 156, 239,
  160, 224,  59,  77, 174,  42, 245, 176, 200, 235, 187,  60, 131,  83, 153,  97,
  23,   43,   4, 126, 186, 119, 214,  38, 225, 105,  20,  99,  85,  33,  12, 125};

const word32 rcon[10]={
  0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000,
  0x20000000, 0x40000000, 0x80000000, 0x1b000000, 0x36000000}; 


void getu32(const byte *a, word32 *b) {
  int i = 0;
  for (i = 0; i < NB; i++) {
    b[i] = (word32)a[4*i] << 24 |
      (word32)a[4*i + 1] << 16    |
      (word32)a[4*i + 2] << 8     |
      (word32)a[4*i + 3];
  }
}


void getu8(const word32 *a, byte *b) {
  int i = 0;
  for (i = 0; i < NB; i++) {
    b[4*i]   = (a[i] >> 24);
    b[4*i + 1] = (a[i] >> 16);
    b[4*i + 2] = (a[i] >> 8);
    b[4*i + 3] = a[i];
  }
}

/* SB to each byte of a 32-bit word by taking
   the correct value in the precomputed tables */
void subWord(word32 *a) {
  *a = (table3[TAKEBYTE(*a,0)] & 0xff000000) |
    (table0[TAKEBYTE(*a,1)] & 0xff0000)      |
    (table0[TAKEBYTE(*a,2)] & 0xff00)        |
    (table1[TAKEBYTE(*a,3)] & 0xff); 
}

/* invMixColumn is included in itableX but is necessary
   for the equivalent key expansion. Implemented as described in 4.1.3
   in "The Design of Rijndael" using a preprocessing followed by MixColumn */
void invMixColumn(word32 *col) {
  byte t, u, v, a[4];
  word32 tmp = 0;

  /* preprocessing */
  u = TAKEBYTE(*col,0) ^ TAKEBYTE(*col, 2);
  u = XTIME(u);
  u = XTIME(u);
  v = TAKEBYTE(*col,1) ^ TAKEBYTE(*col, 3);
  v = XTIME(v);
  v = XTIME(v);
  *col ^= (word32)u << 24 | (word32)v << 16 | (word32)u << 8 | (word32)v;
  
  a[0] = TAKEBYTE(*col, 0);
  a[1] = TAKEBYTE(*col, 1);
  a[2] = TAKEBYTE(*col, 2);
  a[3] = TAKEBYTE(*col, 3);
  
  /* mix column */
  t = a[0] ^ a[1] ^ a[2] ^ a[3];

  v = a[0] ^ a[1];
  v = XTIME(v);
  tmp |= (word32)(a[0] ^ v ^ t) << 24;

  v = a[1] ^ a[2];
  v = XTIME(v);
  tmp |= (word32)(a[1] ^ v ^ t) << 16;

  v = a[2] ^ a[3];
  v = XTIME(v);
  tmp |= (word32)(a[2] ^ v ^ t) << 8;
  
  v = a[3] ^ a[0];
  v = XTIME(v);
  tmp |= (word32)(a[3] ^ v ^ t);

  *col = tmp;
}

void keyExpansion(const word32 key[MAX_WORDS_K], word32 keys[MAX_WORDS_RK], const int NR) {
  word32 temp;
  int i, NK = NR - 6, n = NB*(NR + 1);
  for (i = 0; i < NK; i++) {
    keys[i] = key[i];
  }
  i = NK;
  while (i < n) {
      temp = keys[i - 1];
      if (i % NK == 0) {
        temp = ROTWORD(temp);
        subWord(&temp);
        temp ^= rcon[i/NK - 1];
      }
      else if (NK > 6 && i % NK == 4) {
        subWord(&temp);
      }
      keys[i] = keys[i - NK] ^ temp;
      i++;
  }
}

/* Equivalent key expansion for decryption.
   See 3.7.3 in "The Design of Rijndael" or 5.3.5 in FIPS-197. */
void eqKeyExpansion(const word32 key[MAX_WORDS_K], word32 eq_keys[MAX_WORDS_RK], const int NR) {
  word32 temp;
  int i, NK = NR - 6, n = NB*(NR + 1);
  for (i = 0; i < NK; i++) {
    eq_keys[i] = key[i];
  }
  i = NK;
  while (i < n) {
      temp = eq_keys[i - 1];
      if (i % NK == 0) {
        temp = ROTWORD(temp);
        subWord(&temp);
        temp ^= rcon[i/NK - 1];
      }
      else if (NK > 6 && i % NK == 4) {
        subWord(&temp);
      }
      eq_keys[i] = eq_keys[i - NK] ^ temp;
      i++;
  }
  for (i = NB; i < n - NB; i++) {
    invMixColumn(&eq_keys[i]);
  }
}


void encrypt_aes(const byte input[NB4], byte output[NB4], const word32 keys[MAX_WORDS_RK], const int NR) {
  word32 state[NB], state_tmp[NB];
  int i, round;

  getu32(input, state);
  /* add master key */
  for (i = 0; i < NB; i++) {
    state[i] ^= keys[i];
  }

  /* rounds 1 to NR - 1 */
  for (round = 1; round < NR; round++) {
    for (i=0 ; i<NB ; i++) {
      state_tmp[i] =
        table0[TAKEBYTE(state[i],0)]            ^
        table1[TAKEBYTE(state[(i + 1) % NB],1)] ^
        table2[TAKEBYTE(state[(i + 2) % NB],2)] ^
        table3[TAKEBYTE(state[(i + 3) % NB],3)];
    }
    for (i = 0; i < NB; i++) {
      state[i] = state_tmp[i] ^ keys[round*NB + i];
    }
  }

  /* last round */
  for (i = 0; i < NB; i++) {
    state_tmp[i] = keys[NR*NB + i] ^
      ((table3[TAKEBYTE(state[i % NB],0)] & 0xff000000)     |
       (table0[TAKEBYTE(state[(i + 1) % NB],1)] & 0xff0000) |
       (table0[TAKEBYTE(state[(i + 2) % NB],2)] & 0xff00)   |
       (table1[TAKEBYTE(state[(i + 3) % NB],3)] & 0xff));
  }
  getu8(state_tmp, output);
}


void decrypt_aes(const byte input[NB4], byte output[NB4], const word32 eq_keys[MAX_WORDS_RK], const int NR) {
  word32 state[NB], state_tmp[NB];
  int i, round;

  getu32(input, state);
  /* add master key */
  for (i = 0; i < NB; i++) {
    state[i] ^= eq_keys[NR*NB + i];
  }
  
  /* round NR-1 to round 1 */
  for (round = NR - 1; round > 0; round--) {
    for (i = 0; i < NB; i++) {
      state_tmp[i] =
        itable0[TAKEBYTE(state[i],0)]            ^
        itable1[TAKEBYTE(state[(i + 3) % NB],1)] ^
        itable2[TAKEBYTE(state[(i + 2) % NB],2)] ^
        itable3[TAKEBYTE(state[(i + 1) % NB],3)];
    }
    for (i = 0; i < NB; i++) {
      state[i] = state_tmp[i] ^ eq_keys[round*NB + i];
    }
  }
  
  /* last round */
  for (i = 0; i < NB; i++) {
    state_tmp[i] = eq_keys[i] ^
      ((word32)invsbox[TAKEBYTE(state[i],0)] << 24            |
       (word32)invsbox[TAKEBYTE(state[(i + 3) % NB],1)] << 16 |
       (word32)invsbox[TAKEBYTE(state[(i + 2) % NB],2)] << 8  |
       (word32)invsbox[TAKEBYTE(state[(i + 1) % NB],3)]);
  }
  
  getu8(state_tmp, output);
}