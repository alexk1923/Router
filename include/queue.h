#ifndef _QUEUE_H_
#define _QUEUE_H_

struct queue;
typedef struct queue *queue;

/* create an empty queue */
extern queue queue_create(void);

/* insert an element at the end of the queue */
extern void queue_enq(queue q, void *element);

/* delete the front element on the queue and return it */
extern void *queue_deq(queue q);

/* return a true value if and only if the queue is empty */
extern int queue_empty(queue q);

/* return the first element in the queue */
extern void *queue_peek(queue q);

#endif /* _QUEUE_H_ */
