#ifndef _QUERY_H_
#define _QUERY_H_

#define AND_OP 1
#define OR_OP 2
#define NO_OP 3

#define POINT_COND 4
#define RANGE_COND 5
#define NO_COND 6

#define BITMAP_RET 6
#define COUNT_RET 7
#define SUM_RET 8

using namespace std;
using namespace dorydb;

typedef uint8_t OP_TYPE;
typedef uint8_t COND_TYPE;
typedef uint8_t RET_TYPE;

class Condition
{
    public:
        string table_id;
        COND_TYPE cond_type;
        /* if cond is POINT_COND */
        uint32_t x;
        /* if cond is RANGE_COND */
        uint32_t left_x;
        uint32_t right_x;
};

class Expression
{
    public:
        OP_TYPE op_type;
        /* children expressions NULL if don't continue branching. */
        vector<Expression> exprs;
        /* Conditions NULL if continue branching. */
        vector<Condition> conds;
};

class QueryObj
{
    public:
        string agg_table_id;
        Expression *expr;
};

#endif 
