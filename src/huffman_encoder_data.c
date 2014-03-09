
#include <stdio.h>

#include "huffman.h"

static const size_t huffman_encoder_size = 257;

static const huffman_encoder_entry_t huffman_encoder_table[] = {


    {
      0,
      0x7ffffba,
      27
    },
  

    {
      1,
      0x7ffffbb,
      27
    },
  

    {
      2,
      0x7ffffbc,
      27
    },
  

    {
      3,
      0x7ffffbd,
      27
    },
  

    {
      4,
      0x7ffffbe,
      27
    },
  

    {
      5,
      0x7ffffbf,
      27
    },
  

    {
      6,
      0x7ffffc0,
      27
    },
  

    {
      7,
      0x7ffffc1,
      27
    },
  

    {
      8,
      0x7ffffc2,
      27
    },
  

    {
      9,
      0x7ffffc3,
      27
    },
  

    {
      10,
      0x7ffffc4,
      27
    },
  

    {
      11,
      0x7ffffc5,
      27
    },
  

    {
      12,
      0x7ffffc6,
      27
    },
  

    {
      13,
      0x7ffffc7,
      27
    },
  

    {
      14,
      0x7ffffc8,
      27
    },
  

    {
      15,
      0x7ffffc9,
      27
    },
  

    {
      16,
      0x7ffffca,
      27
    },
  

    {
      17,
      0x7ffffcb,
      27
    },
  

    {
      18,
      0x7ffffcc,
      27
    },
  

    {
      19,
      0x7ffffcd,
      27
    },
  

    {
      20,
      0x7ffffce,
      27
    },
  

    {
      21,
      0x7ffffcf,
      27
    },
  

    {
      22,
      0x7ffffd0,
      27
    },
  

    {
      23,
      0x7ffffd1,
      27
    },
  

    {
      24,
      0x7ffffd2,
      27
    },
  

    {
      25,
      0x7ffffd3,
      27
    },
  

    {
      26,
      0x7ffffd4,
      27
    },
  

    {
      27,
      0x7ffffd5,
      27
    },
  

    {
      28,
      0x7ffffd6,
      27
    },
  

    {
      29,
      0x7ffffd7,
      27
    },
  

    {
      30,
      0x7ffffd8,
      27
    },
  

    {
      31,
      0x7ffffd9,
      27
    },
  

    {
      32,
      0xe8,
      8
    },
  

    {
      33,
      0xffc,
      12
    },
  

    {
      34,
      0x3ffa,
      14
    },
  

    {
      35,
      0x7ffc,
      15
    },
  

    {
      36,
      0x7ffd,
      15
    },
  

    {
      37,
      0x24,
      6
    },
  

    {
      38,
      0x6e,
      7
    },
  

    {
      39,
      0x7ffe,
      15
    },
  

    {
      40,
      0x7fa,
      11
    },
  

    {
      41,
      0x7fb,
      11
    },
  

    {
      42,
      0x3fa,
      10
    },
  

    {
      43,
      0x7fc,
      11
    },
  

    {
      44,
      0xe9,
      8
    },
  

    {
      45,
      0x25,
      6
    },
  

    {
      46,
      0x04,
      5
    },
  

    {
      47,
      0x00,
      4
    },
  

    {
      48,
      0x05,
      5
    },
  

    {
      49,
      0x06,
      5
    },
  

    {
      50,
      0x07,
      5
    },
  

    {
      51,
      0x26,
      6
    },
  

    {
      52,
      0x27,
      6
    },
  

    {
      53,
      0x28,
      6
    },
  

    {
      54,
      0x29,
      6
    },
  

    {
      55,
      0x2a,
      6
    },
  

    {
      56,
      0x2b,
      6
    },
  

    {
      57,
      0x2c,
      6
    },
  

    {
      58,
      0x1ec,
      9
    },
  

    {
      59,
      0xea,
      8
    },
  

    {
      60,
      0x3fffe,
      18
    },
  

    {
      61,
      0x2d,
      6
    },
  

    {
      62,
      0x1fffc,
      17
    },
  

    {
      63,
      0x1ed,
      9
    },
  

    {
      64,
      0x3ffb,
      14
    },
  

    {
      65,
      0x6f,
      7
    },
  

    {
      66,
      0xeb,
      8
    },
  

    {
      67,
      0xec,
      8
    },
  

    {
      68,
      0xed,
      8
    },
  

    {
      69,
      0xee,
      8
    },
  

    {
      70,
      0x70,
      7
    },
  

    {
      71,
      0x1ee,
      9
    },
  

    {
      72,
      0x1ef,
      9
    },
  

    {
      73,
      0x1f0,
      9
    },
  

    {
      74,
      0x1f1,
      9
    },
  

    {
      75,
      0x3fb,
      10
    },
  

    {
      76,
      0x1f2,
      9
    },
  

    {
      77,
      0xef,
      8
    },
  

    {
      78,
      0x1f3,
      9
    },
  

    {
      79,
      0x1f4,
      9
    },
  

    {
      80,
      0x1f5,
      9
    },
  

    {
      81,
      0x1f6,
      9
    },
  

    {
      82,
      0x1f7,
      9
    },
  

    {
      83,
      0xf0,
      8
    },
  

    {
      84,
      0xf1,
      8
    },
  

    {
      85,
      0x1f8,
      9
    },
  

    {
      86,
      0x1f9,
      9
    },
  

    {
      87,
      0x1fa,
      9
    },
  

    {
      88,
      0x1fb,
      9
    },
  

    {
      89,
      0x1fc,
      9
    },
  

    {
      90,
      0x3fc,
      10
    },
  

    {
      91,
      0x3ffc,
      14
    },
  

    {
      92,
      0x7ffffda,
      27
    },
  

    {
      93,
      0x1ffc,
      13
    },
  

    {
      94,
      0x3ffd,
      14
    },
  

    {
      95,
      0x2e,
      6
    },
  

    {
      96,
      0x7fffe,
      19
    },
  

    {
      97,
      0x08,
      5
    },
  

    {
      98,
      0x2f,
      6
    },
  

    {
      99,
      0x09,
      5
    },
  

    {
      100,
      0x30,
      6
    },
  

    {
      101,
      0x01,
      4
    },
  

    {
      102,
      0x31,
      6
    },
  

    {
      103,
      0x32,
      6
    },
  

    {
      104,
      0x33,
      6
    },
  

    {
      105,
      0x0a,
      5
    },
  

    {
      106,
      0x71,
      7
    },
  

    {
      107,
      0x72,
      7
    },
  

    {
      108,
      0x0b,
      5
    },
  

    {
      109,
      0x34,
      6
    },
  

    {
      110,
      0x0c,
      5
    },
  

    {
      111,
      0x0d,
      5
    },
  

    {
      112,
      0x0e,
      5
    },
  

    {
      113,
      0xf2,
      8
    },
  

    {
      114,
      0x0f,
      5
    },
  

    {
      115,
      0x10,
      5
    },
  

    {
      116,
      0x11,
      5
    },
  

    {
      117,
      0x35,
      6
    },
  

    {
      118,
      0x73,
      7
    },
  

    {
      119,
      0x36,
      6
    },
  

    {
      120,
      0xf3,
      8
    },
  

    {
      121,
      0xf4,
      8
    },
  

    {
      122,
      0xf5,
      8
    },
  

    {
      123,
      0x1fffd,
      17
    },
  

    {
      124,
      0x7fd,
      11
    },
  

    {
      125,
      0x1fffe,
      17
    },
  

    {
      126,
      0xffd,
      12
    },
  

    {
      127,
      0x7ffffdb,
      27
    },
  

    {
      128,
      0x7ffffdc,
      27
    },
  

    {
      129,
      0x7ffffdd,
      27
    },
  

    {
      130,
      0x7ffffde,
      27
    },
  

    {
      131,
      0x7ffffdf,
      27
    },
  

    {
      132,
      0x7ffffe0,
      27
    },
  

    {
      133,
      0x7ffffe1,
      27
    },
  

    {
      134,
      0x7ffffe2,
      27
    },
  

    {
      135,
      0x7ffffe3,
      27
    },
  

    {
      136,
      0x7ffffe4,
      27
    },
  

    {
      137,
      0x7ffffe5,
      27
    },
  

    {
      138,
      0x7ffffe6,
      27
    },
  

    {
      139,
      0x7ffffe7,
      27
    },
  

    {
      140,
      0x7ffffe8,
      27
    },
  

    {
      141,
      0x7ffffe9,
      27
    },
  

    {
      142,
      0x7ffffea,
      27
    },
  

    {
      143,
      0x7ffffeb,
      27
    },
  

    {
      144,
      0x7ffffec,
      27
    },
  

    {
      145,
      0x7ffffed,
      27
    },
  

    {
      146,
      0x7ffffee,
      27
    },
  

    {
      147,
      0x7ffffef,
      27
    },
  

    {
      148,
      0x7fffff0,
      27
    },
  

    {
      149,
      0x7fffff1,
      27
    },
  

    {
      150,
      0x7fffff2,
      27
    },
  

    {
      151,
      0x7fffff3,
      27
    },
  

    {
      152,
      0x7fffff4,
      27
    },
  

    {
      153,
      0x7fffff5,
      27
    },
  

    {
      154,
      0x7fffff6,
      27
    },
  

    {
      155,
      0x7fffff7,
      27
    },
  

    {
      156,
      0x7fffff8,
      27
    },
  

    {
      157,
      0x7fffff9,
      27
    },
  

    {
      158,
      0x7fffffa,
      27
    },
  

    {
      159,
      0x7fffffb,
      27
    },
  

    {
      160,
      0x7fffffc,
      27
    },
  

    {
      161,
      0x7fffffd,
      27
    },
  

    {
      162,
      0x7fffffe,
      27
    },
  

    {
      163,
      0x7ffffff,
      27
    },
  

    {
      164,
      0x3ffff80,
      26
    },
  

    {
      165,
      0x3ffff81,
      26
    },
  

    {
      166,
      0x3ffff82,
      26
    },
  

    {
      167,
      0x3ffff83,
      26
    },
  

    {
      168,
      0x3ffff84,
      26
    },
  

    {
      169,
      0x3ffff85,
      26
    },
  

    {
      170,
      0x3ffff86,
      26
    },
  

    {
      171,
      0x3ffff87,
      26
    },
  

    {
      172,
      0x3ffff88,
      26
    },
  

    {
      173,
      0x3ffff89,
      26
    },
  

    {
      174,
      0x3ffff8a,
      26
    },
  

    {
      175,
      0x3ffff8b,
      26
    },
  

    {
      176,
      0x3ffff8c,
      26
    },
  

    {
      177,
      0x3ffff8d,
      26
    },
  

    {
      178,
      0x3ffff8e,
      26
    },
  

    {
      179,
      0x3ffff8f,
      26
    },
  

    {
      180,
      0x3ffff90,
      26
    },
  

    {
      181,
      0x3ffff91,
      26
    },
  

    {
      182,
      0x3ffff92,
      26
    },
  

    {
      183,
      0x3ffff93,
      26
    },
  

    {
      184,
      0x3ffff94,
      26
    },
  

    {
      185,
      0x3ffff95,
      26
    },
  

    {
      186,
      0x3ffff96,
      26
    },
  

    {
      187,
      0x3ffff97,
      26
    },
  

    {
      188,
      0x3ffff98,
      26
    },
  

    {
      189,
      0x3ffff99,
      26
    },
  

    {
      190,
      0x3ffff9a,
      26
    },
  

    {
      191,
      0x3ffff9b,
      26
    },
  

    {
      192,
      0x3ffff9c,
      26
    },
  

    {
      193,
      0x3ffff9d,
      26
    },
  

    {
      194,
      0x3ffff9e,
      26
    },
  

    {
      195,
      0x3ffff9f,
      26
    },
  

    {
      196,
      0x3ffffa0,
      26
    },
  

    {
      197,
      0x3ffffa1,
      26
    },
  

    {
      198,
      0x3ffffa2,
      26
    },
  

    {
      199,
      0x3ffffa3,
      26
    },
  

    {
      200,
      0x3ffffa4,
      26
    },
  

    {
      201,
      0x3ffffa5,
      26
    },
  

    {
      202,
      0x3ffffa6,
      26
    },
  

    {
      203,
      0x3ffffa7,
      26
    },
  

    {
      204,
      0x3ffffa8,
      26
    },
  

    {
      205,
      0x3ffffa9,
      26
    },
  

    {
      206,
      0x3ffffaa,
      26
    },
  

    {
      207,
      0x3ffffab,
      26
    },
  

    {
      208,
      0x3ffffac,
      26
    },
  

    {
      209,
      0x3ffffad,
      26
    },
  

    {
      210,
      0x3ffffae,
      26
    },
  

    {
      211,
      0x3ffffaf,
      26
    },
  

    {
      212,
      0x3ffffb0,
      26
    },
  

    {
      213,
      0x3ffffb1,
      26
    },
  

    {
      214,
      0x3ffffb2,
      26
    },
  

    {
      215,
      0x3ffffb3,
      26
    },
  

    {
      216,
      0x3ffffb4,
      26
    },
  

    {
      217,
      0x3ffffb5,
      26
    },
  

    {
      218,
      0x3ffffb6,
      26
    },
  

    {
      219,
      0x3ffffb7,
      26
    },
  

    {
      220,
      0x3ffffb8,
      26
    },
  

    {
      221,
      0x3ffffb9,
      26
    },
  

    {
      222,
      0x3ffffba,
      26
    },
  

    {
      223,
      0x3ffffbb,
      26
    },
  

    {
      224,
      0x3ffffbc,
      26
    },
  

    {
      225,
      0x3ffffbd,
      26
    },
  

    {
      226,
      0x3ffffbe,
      26
    },
  

    {
      227,
      0x3ffffbf,
      26
    },
  

    {
      228,
      0x3ffffc0,
      26
    },
  

    {
      229,
      0x3ffffc1,
      26
    },
  

    {
      230,
      0x3ffffc2,
      26
    },
  

    {
      231,
      0x3ffffc3,
      26
    },
  

    {
      232,
      0x3ffffc4,
      26
    },
  

    {
      233,
      0x3ffffc5,
      26
    },
  

    {
      234,
      0x3ffffc6,
      26
    },
  

    {
      235,
      0x3ffffc7,
      26
    },
  

    {
      236,
      0x3ffffc8,
      26
    },
  

    {
      237,
      0x3ffffc9,
      26
    },
  

    {
      238,
      0x3ffffca,
      26
    },
  

    {
      239,
      0x3ffffcb,
      26
    },
  

    {
      240,
      0x3ffffcc,
      26
    },
  

    {
      241,
      0x3ffffcd,
      26
    },
  

    {
      242,
      0x3ffffce,
      26
    },
  

    {
      243,
      0x3ffffcf,
      26
    },
  

    {
      244,
      0x3ffffd0,
      26
    },
  

    {
      245,
      0x3ffffd1,
      26
    },
  

    {
      246,
      0x3ffffd2,
      26
    },
  

    {
      247,
      0x3ffffd3,
      26
    },
  

    {
      248,
      0x3ffffd4,
      26
    },
  

    {
      249,
      0x3ffffd5,
      26
    },
  

    {
      250,
      0x3ffffd6,
      26
    },
  

    {
      251,
      0x3ffffd7,
      26
    },
  

    {
      252,
      0x3ffffd8,
      26
    },
  

    {
      253,
      0x3ffffd9,
      26
    },
  

    {
      254,
      0x3ffffda,
      26
    },
  

    {
      255,
      0x3ffffdb,
      26
    },
  

    {
      256,
      0x3ffffdc,
      26
    },
  
};
