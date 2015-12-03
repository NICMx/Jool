/*
 * This implementation assumes all Telnet NVM commands are two bytes long,
 * except the option negotiation ones, which are 3 bytes long.
 * (we will always reject option negotiation, so there will be no
 * subnegotiations.)
 */

#include "nat64/mod/common/alg/ftp/parser/telnet.h"

#define WILL	251
#define DO	253
#define IAC	255
#define CR	0x0d
#define LF	0x0a

#define BUFFER_LEN 232


struct buffer_chunk {
	struct sk_buff *skb;

	unsigned char chunk[BUFFER_LEN];
	/* Last byte index read from @chunk. -1 if no bytes have been read. */
	int cursor;
	/* Chunk offset within the packet. */
	unsigned int offset;
	/* Actual amount of bytes copied to @chunk. */
	unsigned int len;
};


static struct buffer_chunk *create_buffer(struct sk_buff *skb,
		unsigned int offset)
{
	struct buffer_chunk *buffer;

	buffer = kmalloc(sizeof(*buffer), GFP_ATOMIC);
	if (!buffer)
		return NULL;

	buffer->skb = skb;
	buffer->cursor = -1;
	buffer->offset = offset;
	buffer->len = 0;
	return buffer;
}

static int fetch_next_buffer_block(struct buffer_chunk *buffer)
{
	struct sk_buff *skb = buffer->skb;
	unsigned int read_len;
	int error;

	read_len = (buffer->offset + BUFFER_LEN > skb->len)
			? (skb->len - buffer->offset)
			: BUFFER_LEN;
	error = skb_copy_bits(skb, buffer->offset, buffer, read_len);
	if (error)
		return error;

	buffer->cursor = -1;
	buffer->offset += read_len;
	buffer->len = read_len;
	return 0;
}

static int fetch_next_chara(struct buffer_chunk *buffer, unsigned char *chara)
{
	int error;

	if (buffer->cursor >= buffer->len - 1) {
		error = fetch_next_buffer_block(buffer);
		if (error)
			return error;
	}

	buffer->cursor++;
	*chara = buffer->chunk[buffer->cursor];
	return 0;
}

static int add_chunk(struct list_head *chunks, struct buffer_chunk *buffer,
		enum telnet_type type)
{
	struct telnet_chunk *chunk;

	chunk = kmalloc(sizeof(*chunk), GFP_ATOMIC);
	if (!chunk)
		return -ENOMEM;

	chunk->type = type;
	chunk->offset = buffer->offset + buffer->cursor;
	list_add_tail(&chunk->list_hook, chunks);
	return 0;
}

static void clean_chunks(struct list_head *chunks)
{
	struct telnet_chunk *chunk;

	while (!list_empty(chunks)) {
		chunk = list_first_entry(chunks, typeof(*chunk), list_hook);
		list_del(&chunk->list_hook);
		kfree(chunk);
	}
}

/**
 * Reads skb's payload (ie. starting from offset), and builds a list (@chunks)
 * of descriptors of the message structure. The payload is assumed to be
 * telnet-formatted.
 *
 * For example, from this packet payload:
 *
 *     foo<IAC><AO>bar<IAC><DO><TRANSMIT-BINARY>foo<CR>bar<CR><LF>foo<CR><LF>
 *
 * The resulting list is
 *
 *     bytes 0-2: non-terminated text
 *     bytes 3-4: command
 *     bytes 5-7: non-terminated text
 *     bytes 8-10: option
 *     bytes 11-19: terminated text
 *     bytes 20-24: terminated text
 *
 * TODO I need to test this hard.
 * In particular, it can probably add redundant text chunks to the list if there
 * are telnet commands at the beginning or end of the payload.
 * Also, CRLF is not implemented yet lulz.
 *
 * TODO still not implemented: watch out for
 *
 *     foo<CR><IAC><AO><LF>
 *
 * which yields
 *
 *     bytes 0-3: non-terminated text
 *     bytes 4-5: command
 *     bytes 6-6: terminated text
 */
int telnet_parse(struct sk_buff *skb, unsigned int offset,
		struct list_head *chunks)
{
	struct buffer_chunk *buffer;
	unsigned char chara;
	int error;

	buffer = create_buffer(skb, offset);
	if (!buffer)
		return -ENOMEM;
	INIT_LIST_HEAD(chunks);

	do {
		error = fetch_next_chara(buffer, &chara);
		if (error)
			goto fail;
		if (chara != IAC)
			continue;

		error = add_chunk(chunks, buffer, TELNET_TEXT);
		if (error)
			goto fail;

		/* Consume the command code. */
		error = fetch_next_chara(buffer, &chara);
		if (error)
			goto fail;

		switch (chara) {
		case WILL:
		case DO:
			/* Consume (and waste) the option ID. */
			error = fetch_next_chara(buffer, &chara);
			if (error)
				goto fail;
			error = add_chunk(chunks, buffer, TELNET_OPT);
			break;
		default:
			error = add_chunk(chunks, buffer, TELNET_COMMAND);
			break;
		}

		if (error)
			goto fail;
	} while (buffer->offset + buffer->cursor < skb->len);

	return add_chunk(chunks, buffer, TELNET_TEXT);

fail:
	clean_chunks(chunks);
	return error;
}

struct telnet_chunk *telnet_chunk_entry(struct list_head *node)
{
	return list_entry(node, struct telnet_chunk, list_hook);
}
