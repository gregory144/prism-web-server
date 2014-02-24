
#include <stdio.h>

#include "huffman.h"

static const size_t huffman_encoder_size = 257;

static const huffman_encoder_entry_t huffman_encoder_table[] = {


    {
      0,
      0x1ffffbc,
      25
    },
  

    {
      1,
      0x1ffffbd,
      25
    },
  

    {
      2,
      0x1ffffbe,
      25
    },
  

    {
      3,
      0x1ffffbf,
      25
    },
  

    {
      4,
      0x1ffffc0,
      25
    },
  

    {
      5,
      0x1ffffc1,
      25
    },
  

    {
      6,
      0x1ffffc2,
      25
    },
  

    {
      7,
      0x1ffffc3,
      25
    },
  

    {
      8,
      0x1ffffc4,
      25
    },
  

    {
      9,
      0x1ffffc5,
      25
    },
  

    {
      10,
      0x1ffffc6,
      25
    },
  

    {
      11,
      0x1ffffc7,
      25
    },
  

    {
      12,
      0x1ffffc8,
      25
    },
  

    {
      13,
      0x1ffffc9,
      25
    },
  

    {
      14,
      0x1ffffca,
      25
    },
  

    {
      15,
      0x1ffffcb,
      25
    },
  

    {
      16,
      0x1ffffcc,
      25
    },
  

    {
      17,
      0x1ffffcd,
      25
    },
  

    {
      18,
      0x1ffffce,
      25
    },
  

    {
      19,
      0x1ffffcf,
      25
    },
  

    {
      20,
      0x1ffffd0,
      25
    },
  

    {
      21,
      0x1ffffd1,
      25
    },
  

    {
      22,
      0x1ffffd2,
      25
    },
  

    {
      23,
      0x1ffffd3,
      25
    },
  

    {
      24,
      0x1ffffd4,
      25
    },
  

    {
      25,
      0x1ffffd5,
      25
    },
  

    {
      26,
      0x1ffffd6,
      25
    },
  

    {
      27,
      0x1ffffd7,
      25
    },
  

    {
      28,
      0x1ffffd8,
      25
    },
  

    {
      29,
      0x1ffffd9,
      25
    },
  

    {
      30,
      0x1ffffda,
      25
    },
  

    {
      31,
      0x1ffffdb,
      25
    },
  

    {
      32,
      0x00,
      4
    },
  

    {
      33,
      0xffa,
      12
    },
  

    {
      34,
      0x6a,
      7
    },
  

    {
      35,
      0x1ffa,
      13
    },
  

    {
      36,
      0x3ffc,
      14
    },
  

    {
      37,
      0x1ec,
      9
    },
  

    {
      38,
      0x3f8,
      10
    },
  

    {
      39,
      0x1ffb,
      13
    },
  

    {
      40,
      0x1ed,
      9
    },
  

    {
      41,
      0x1ee,
      9
    },
  

    {
      42,
      0xffb,
      12
    },
  

    {
      43,
      0x7fa,
      11
    },
  

    {
      44,
      0x22,
      6
    },
  

    {
      45,
      0x23,
      6
    },
  

    {
      46,
      0x24,
      6
    },
  

    {
      47,
      0x6b,
      7
    },
  

    {
      48,
      0x01,
      4
    },
  

    {
      49,
      0x02,
      4
    },
  

    {
      50,
      0x03,
      4
    },
  

    {
      51,
      0x08,
      5
    },
  

    {
      52,
      0x09,
      5
    },
  

    {
      53,
      0x0a,
      5
    },
  

    {
      54,
      0x25,
      6
    },
  

    {
      55,
      0x26,
      6
    },
  

    {
      56,
      0x0b,
      5
    },
  

    {
      57,
      0x0c,
      5
    },
  

    {
      58,
      0x0d,
      5
    },
  

    {
      59,
      0x1ef,
      9
    },
  

    {
      60,
      0xfffa,
      16
    },
  

    {
      61,
      0x6c,
      7
    },
  

    {
      62,
      0x1ffc,
      13
    },
  

    {
      63,
      0xffc,
      12
    },
  

    {
      64,
      0xfffb,
      16
    },
  

    {
      65,
      0x6d,
      7
    },
  

    {
      66,
      0xea,
      8
    },
  

    {
      67,
      0xeb,
      8
    },
  

    {
      68,
      0xec,
      8
    },
  

    {
      69,
      0xed,
      8
    },
  

    {
      70,
      0xee,
      8
    },
  

    {
      71,
      0x27,
      6
    },
  

    {
      72,
      0x1f0,
      9
    },
  

    {
      73,
      0xef,
      8
    },
  

    {
      74,
      0xf0,
      8
    },
  

    {
      75,
      0x3f9,
      10
    },
  

    {
      76,
      0x1f1,
      9
    },
  

    {
      77,
      0x28,
      6
    },
  

    {
      78,
      0xf1,
      8
    },
  

    {
      79,
      0xf2,
      8
    },
  

    {
      80,
      0x1f2,
      9
    },
  

    {
      81,
      0x3fa,
      10
    },
  

    {
      82,
      0x1f3,
      9
    },
  

    {
      83,
      0x29,
      6
    },
  

    {
      84,
      0x0e,
      5
    },
  

    {
      85,
      0x1f4,
      9
    },
  

    {
      86,
      0x1f5,
      9
    },
  

    {
      87,
      0xf3,
      8
    },
  

    {
      88,
      0x3fb,
      10
    },
  

    {
      89,
      0x1f6,
      9
    },
  

    {
      90,
      0x3fc,
      10
    },
  

    {
      91,
      0x7fb,
      11
    },
  

    {
      92,
      0x1ffd,
      13
    },
  

    {
      93,
      0x7fc,
      11
    },
  

    {
      94,
      0x7ffc,
      15
    },
  

    {
      95,
      0x1f7,
      9
    },
  

    {
      96,
      0x1fffe,
      17
    },
  

    {
      97,
      0x0f,
      5
    },
  

    {
      98,
      0x6e,
      7
    },
  

    {
      99,
      0x2a,
      6
    },
  

    {
      100,
      0x2b,
      6
    },
  

    {
      101,
      0x10,
      5
    },
  

    {
      102,
      0x6f,
      7
    },
  

    {
      103,
      0x70,
      7
    },
  

    {
      104,
      0x71,
      7
    },
  

    {
      105,
      0x2c,
      6
    },
  

    {
      106,
      0x1f8,
      9
    },
  

    {
      107,
      0x1f9,
      9
    },
  

    {
      108,
      0x72,
      7
    },
  

    {
      109,
      0x2d,
      6
    },
  

    {
      110,
      0x2e,
      6
    },
  

    {
      111,
      0x2f,
      6
    },
  

    {
      112,
      0x30,
      6
    },
  

    {
      113,
      0x1fa,
      9
    },
  

    {
      114,
      0x31,
      6
    },
  

    {
      115,
      0x32,
      6
    },
  

    {
      116,
      0x33,
      6
    },
  

    {
      117,
      0x34,
      6
    },
  

    {
      118,
      0x73,
      7
    },
  

    {
      119,
      0xf4,
      8
    },
  

    {
      120,
      0x74,
      7
    },
  

    {
      121,
      0xf5,
      8
    },
  

    {
      122,
      0x1fb,
      9
    },
  

    {
      123,
      0xfffc,
      16
    },
  

    {
      124,
      0x3ffd,
      14
    },
  

    {
      125,
      0xfffd,
      16
    },
  

    {
      126,
      0xfffe,
      16
    },
  

    {
      127,
      0x1ffffdc,
      25
    },
  

    {
      128,
      0x1ffffdd,
      25
    },
  

    {
      129,
      0x1ffffde,
      25
    },
  

    {
      130,
      0x1ffffdf,
      25
    },
  

    {
      131,
      0x1ffffe0,
      25
    },
  

    {
      132,
      0x1ffffe1,
      25
    },
  

    {
      133,
      0x1ffffe2,
      25
    },
  

    {
      134,
      0x1ffffe3,
      25
    },
  

    {
      135,
      0x1ffffe4,
      25
    },
  

    {
      136,
      0x1ffffe5,
      25
    },
  

    {
      137,
      0x1ffffe6,
      25
    },
  

    {
      138,
      0x1ffffe7,
      25
    },
  

    {
      139,
      0x1ffffe8,
      25
    },
  

    {
      140,
      0x1ffffe9,
      25
    },
  

    {
      141,
      0x1ffffea,
      25
    },
  

    {
      142,
      0x1ffffeb,
      25
    },
  

    {
      143,
      0x1ffffec,
      25
    },
  

    {
      144,
      0x1ffffed,
      25
    },
  

    {
      145,
      0x1ffffee,
      25
    },
  

    {
      146,
      0x1ffffef,
      25
    },
  

    {
      147,
      0x1fffff0,
      25
    },
  

    {
      148,
      0x1fffff1,
      25
    },
  

    {
      149,
      0x1fffff2,
      25
    },
  

    {
      150,
      0x1fffff3,
      25
    },
  

    {
      151,
      0x1fffff4,
      25
    },
  

    {
      152,
      0x1fffff5,
      25
    },
  

    {
      153,
      0x1fffff6,
      25
    },
  

    {
      154,
      0x1fffff7,
      25
    },
  

    {
      155,
      0x1fffff8,
      25
    },
  

    {
      156,
      0x1fffff9,
      25
    },
  

    {
      157,
      0x1fffffa,
      25
    },
  

    {
      158,
      0x1fffffb,
      25
    },
  

    {
      159,
      0x1fffffc,
      25
    },
  

    {
      160,
      0x1fffffd,
      25
    },
  

    {
      161,
      0x1fffffe,
      25
    },
  

    {
      162,
      0x1ffffff,
      25
    },
  

    {
      163,
      0xffff80,
      24
    },
  

    {
      164,
      0xffff81,
      24
    },
  

    {
      165,
      0xffff82,
      24
    },
  

    {
      166,
      0xffff83,
      24
    },
  

    {
      167,
      0xffff84,
      24
    },
  

    {
      168,
      0xffff85,
      24
    },
  

    {
      169,
      0xffff86,
      24
    },
  

    {
      170,
      0xffff87,
      24
    },
  

    {
      171,
      0xffff88,
      24
    },
  

    {
      172,
      0xffff89,
      24
    },
  

    {
      173,
      0xffff8a,
      24
    },
  

    {
      174,
      0xffff8b,
      24
    },
  

    {
      175,
      0xffff8c,
      24
    },
  

    {
      176,
      0xffff8d,
      24
    },
  

    {
      177,
      0xffff8e,
      24
    },
  

    {
      178,
      0xffff8f,
      24
    },
  

    {
      179,
      0xffff90,
      24
    },
  

    {
      180,
      0xffff91,
      24
    },
  

    {
      181,
      0xffff92,
      24
    },
  

    {
      182,
      0xffff93,
      24
    },
  

    {
      183,
      0xffff94,
      24
    },
  

    {
      184,
      0xffff95,
      24
    },
  

    {
      185,
      0xffff96,
      24
    },
  

    {
      186,
      0xffff97,
      24
    },
  

    {
      187,
      0xffff98,
      24
    },
  

    {
      188,
      0xffff99,
      24
    },
  

    {
      189,
      0xffff9a,
      24
    },
  

    {
      190,
      0xffff9b,
      24
    },
  

    {
      191,
      0xffff9c,
      24
    },
  

    {
      192,
      0xffff9d,
      24
    },
  

    {
      193,
      0xffff9e,
      24
    },
  

    {
      194,
      0xffff9f,
      24
    },
  

    {
      195,
      0xffffa0,
      24
    },
  

    {
      196,
      0xffffa1,
      24
    },
  

    {
      197,
      0xffffa2,
      24
    },
  

    {
      198,
      0xffffa3,
      24
    },
  

    {
      199,
      0xffffa4,
      24
    },
  

    {
      200,
      0xffffa5,
      24
    },
  

    {
      201,
      0xffffa6,
      24
    },
  

    {
      202,
      0xffffa7,
      24
    },
  

    {
      203,
      0xffffa8,
      24
    },
  

    {
      204,
      0xffffa9,
      24
    },
  

    {
      205,
      0xffffaa,
      24
    },
  

    {
      206,
      0xffffab,
      24
    },
  

    {
      207,
      0xffffac,
      24
    },
  

    {
      208,
      0xffffad,
      24
    },
  

    {
      209,
      0xffffae,
      24
    },
  

    {
      210,
      0xffffaf,
      24
    },
  

    {
      211,
      0xffffb0,
      24
    },
  

    {
      212,
      0xffffb1,
      24
    },
  

    {
      213,
      0xffffb2,
      24
    },
  

    {
      214,
      0xffffb3,
      24
    },
  

    {
      215,
      0xffffb4,
      24
    },
  

    {
      216,
      0xffffb5,
      24
    },
  

    {
      217,
      0xffffb6,
      24
    },
  

    {
      218,
      0xffffb7,
      24
    },
  

    {
      219,
      0xffffb8,
      24
    },
  

    {
      220,
      0xffffb9,
      24
    },
  

    {
      221,
      0xffffba,
      24
    },
  

    {
      222,
      0xffffbb,
      24
    },
  

    {
      223,
      0xffffbc,
      24
    },
  

    {
      224,
      0xffffbd,
      24
    },
  

    {
      225,
      0xffffbe,
      24
    },
  

    {
      226,
      0xffffbf,
      24
    },
  

    {
      227,
      0xffffc0,
      24
    },
  

    {
      228,
      0xffffc1,
      24
    },
  

    {
      229,
      0xffffc2,
      24
    },
  

    {
      230,
      0xffffc3,
      24
    },
  

    {
      231,
      0xffffc4,
      24
    },
  

    {
      232,
      0xffffc5,
      24
    },
  

    {
      233,
      0xffffc6,
      24
    },
  

    {
      234,
      0xffffc7,
      24
    },
  

    {
      235,
      0xffffc8,
      24
    },
  

    {
      236,
      0xffffc9,
      24
    },
  

    {
      237,
      0xffffca,
      24
    },
  

    {
      238,
      0xffffcb,
      24
    },
  

    {
      239,
      0xffffcc,
      24
    },
  

    {
      240,
      0xffffcd,
      24
    },
  

    {
      241,
      0xffffce,
      24
    },
  

    {
      242,
      0xffffcf,
      24
    },
  

    {
      243,
      0xffffd0,
      24
    },
  

    {
      244,
      0xffffd1,
      24
    },
  

    {
      245,
      0xffffd2,
      24
    },
  

    {
      246,
      0xffffd3,
      24
    },
  

    {
      247,
      0xffffd4,
      24
    },
  

    {
      248,
      0xffffd5,
      24
    },
  

    {
      249,
      0xffffd6,
      24
    },
  

    {
      250,
      0xffffd7,
      24
    },
  

    {
      251,
      0xffffd8,
      24
    },
  

    {
      252,
      0xffffd9,
      24
    },
  

    {
      253,
      0xffffda,
      24
    },
  

    {
      254,
      0xffffdb,
      24
    },
  

    {
      255,
      0xffffdc,
      24
    },
  

    {
      256,
      0xffffdd,
      24
    },
  
};
