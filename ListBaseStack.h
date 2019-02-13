#ifndef __LB_STACK_H__
#define __LB_STACK_H__

#define TRUE	1
#define FALSE	0

typedef int Data;

typedef struct _node
{
	char data[100]; 
	struct _node * next;
	struct _node * prev; 
} Node;

typedef struct _listStack
{
	Node* head;
	Node* cur; 
	int number; 
}ListStack;


typedef ListStack Stack;

void StackInit(Stack * pstack);
int SIsEmpty(Stack * pstack);

void SPush(Stack * pstack, char* data);
Data SPop(Stack * pstack);
Data SPeek(Stack * pstack);
void data_search(Stack* pstack); 
//command 위 
//command 아래 

#endif
