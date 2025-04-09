#include "model/batch_utils.h"
namespace model {

record_batch
make_ghost_batch(offset start_offset, offset end_offset, term_id term) {
    auto delta = end_offset - start_offset;
    auto now = timestamp::now();
    record_batch_header header = {
      .size_bytes = packed_record_batch_header_size,
      .base_offset = start_offset,
      .type = record_batch_type::ghost_batch,
      .crc = 0, // crc computed later
      .attrs = record_batch_attributes{} |= compression::none,
      .last_offset_delta = static_cast<int32_t>(delta),
      .first_timestamp = now,
      .max_timestamp = now,
      .producer_id = -1,
      .producer_epoch = -1,
      .base_sequence = -1,
      .record_count = static_cast<int32_t>(delta() + 1),
      .ctx = record_batch_header::context(term, ss::this_shard_id())};

    record_batch batch(header, record_batch::compressed_records{});

    batch.header().crc = crc_record_batch(batch);
    batch.header().header_crc = internal_header_only_crc(batch.header());
    return batch;
}

std::vector<record_batch>
make_ghost_batches(offset start_offset, offset end_offset, term_id term) {
    std::vector<record_batch> batches;
    while (start_offset <= end_offset) {
        static constexpr offset max_batch_size{
          std::numeric_limits<int32_t>::max()};
        // limit max batch size
        const offset delta = std::min<offset>(
          max_batch_size, end_offset - start_offset);

        batches.push_back(
          make_ghost_batch(start_offset, delta + start_offset, term));
        start_offset = next_offset(batches.back().last_offset());
    }

    return batches;
}

} // namespace model
