use crate::heap::*;
use crate::trap::*;
use crate::value::*;
use crate::*;
use std::mem::size_of;

impl ScriptHeap {
    // Arrays

    fn prepare_array_storage_growth(
        &mut self,
        array: ScriptArray,
        requested_len: usize,
    ) -> Option<usize> {
        let storage = &self.arrays[array].storage;
        let before = storage.retained_bytes();
        if self.max_heap_bytes.is_none() {
            return Some(before);
        }
        let growth = storage
            .minimum_bytes_for_len(requested_len)
            .map(|required| required.saturating_sub(before));
        if self.can_grow_heap_by(growth) {
            Some(before)
        } else {
            None
        }
    }

    pub(crate) fn note_array_storage_growth(&mut self, array: ScriptArray, before: usize) {
        let after = self.arrays[array].storage.retained_bytes();
        self.note_heap_capacity_change(before, after);
    }

    pub fn freeze_array(&mut self, array: ScriptArray) {
        self.arrays[array].tag.freeze()
    }

    pub fn new_array(&mut self) -> ScriptArray {
        let capacity = self.arrays.capacity();
        let (array, previous_storage) = if let Some(arr) = self.arrays_free.pop() {
            // arr already has the correct generation from gc.rs sweep
            let array = &mut self.arrays[arr];
            let previous_storage = array.storage.retained_bytes();
            // Reused array slots may come from typed buffers (U8/U16/U32/F32).
            // New arrays must start as generic ScriptValue storage.
            if !matches!(array.storage, ScriptArrayStorage::ScriptValue(_)) {
                array.storage = ScriptArrayStorage::ScriptValue(Default::default());
            } else {
                array.storage.clear();
            }
            array.tag.set_alloced();
            (arr, previous_storage)
        } else {
            let index = self.arrays.len();
            let mut array = ScriptArrayData::default();
            array.tag.set_alloced();
            self.arrays.push(array);
            // New slot starts at generation 0
            (ScriptArray::new(index as _, crate::value::GENERATION_ZERO), 0)
        };
        self.note_heap_growth(
            self.arrays
                .capacity()
                .saturating_sub(capacity)
                .saturating_mul(size_of::<crate::gen_index::GenSlot<ScriptArrayData>>()),
        );
        self.note_heap_capacity_change(
            previous_storage,
            self.arrays[array].storage.retained_bytes(),
        );
        array
    }

    pub fn array_len(&self, array: ScriptArray) -> usize {
        self.arrays[array].storage.len()
    }

    pub fn array_push(&mut self, array: ScriptArray, value: ScriptValue, trap: ScriptTrap) {
        if self.arrays[array].tag.is_immutable() {
            script_err_immutable!(trap, "array is immutable");
            return;
        }
        let Some(requested_len) = self.arrays[array].storage.len().checked_add(1) else {
            self.can_grow_heap_by(None);
            return;
        };
        let Some(before) = self.prepare_array_storage_growth(array, requested_len) else {
            return;
        };
        {
            let array_data = &mut self.arrays[array];
            array_data.tag.set_dirty();
            array_data.storage.push(value);
        }
        self.note_array_storage_growth(array, before);
    }

    pub fn array_pop_front_option(&mut self, array: ScriptArray) -> Option<ScriptValue> {
        let array = &mut self.arrays[array];
        if array.tag.is_immutable() {
            return None;
        }
        array.tag.set_dirty();
        array.storage.pop_front()
    }

    pub fn array_push_vec(&mut self, array: ScriptArray, object: ScriptObject, trap: ScriptTrap) {
        if self.arrays[array].tag.is_immutable() {
            script_err_immutable!(trap, "array is immutable");
            return;
        }
        let Some(requested_len) = self.arrays[array]
            .storage
            .len()
            .checked_add(self.objects[object].vec.len())
        else {
            self.can_grow_heap_by(None);
            return;
        };
        let Some(before) = self.prepare_array_storage_growth(array, requested_len) else {
            return;
        };
        let values = self.objects[object]
            .vec
            .iter()
            .map(|entry| entry.value)
            .collect::<Vec<_>>();
        {
            let array_data = &mut self.arrays[array];
            array_data.tag.set_dirty();
            for value in values {
                array_data.storage.push(value);
            }
        }
        self.note_array_storage_growth(array, before);
    }

    /// Merges all elements from source array into target array.
    /// Used by the splat operator (..) to spread one array into another.
    pub fn merge_array(&mut self, target: ScriptArray, source: ScriptArray, trap: ScriptTrap) {
        if self.arrays[target].tag.is_immutable() {
            script_err_immutable!(trap, "array is immutable");
            return;
        }
        // Get the storage from source first
        let source_storage = &self.arrays[source].storage;
        let values: Vec<ScriptValue> = match source_storage {
            ScriptArrayStorage::ScriptValue(v) => v.iter().copied().collect(),
            ScriptArrayStorage::U8(v) => {
                v.iter().map(|x| ScriptValue::from_f64(*x as f64)).collect()
            }
            ScriptArrayStorage::U16(v) => {
                v.iter().map(|x| ScriptValue::from_f64(*x as f64)).collect()
            }
            ScriptArrayStorage::U32(v) => {
                v.iter().map(|x| ScriptValue::from_f64(*x as f64)).collect()
            }
            ScriptArrayStorage::F32(v) => {
                v.iter().map(|x| ScriptValue::from_f64(*x as f64)).collect()
            }
        };

        let Some(requested_len) = self.arrays[target].storage.len().checked_add(values.len()) else {
            self.can_grow_heap_by(None);
            return;
        };
        let Some(before) = self.prepare_array_storage_growth(target, requested_len) else {
            return;
        };
        let target_arr = &mut self.arrays[target];
        target_arr.tag.set_dirty();
        for v in values {
            target_arr.storage.push(v);
        }
        self.note_array_storage_growth(target, before);
    }

    pub fn array_push_unchecked(&mut self, array: ScriptArray, value: ScriptValue) {
        let Some(requested_len) = self.arrays[array].storage.len().checked_add(1) else {
            self.can_grow_heap_by(None);
            return;
        };
        let Some(before) = self.prepare_array_storage_growth(array, requested_len) else {
            return;
        };
        {
            let array_data = &mut self.arrays[array];
            array_data.tag.set_dirty();
            array_data.storage.push(value);
        }
        self.note_array_storage_growth(array, before);
    }

    pub fn array_storage(&self, array: ScriptArray) -> &ScriptArrayStorage {
        let array = &self.arrays[array];
        &array.storage
    }

    pub fn new_array_from_vec_u8(&mut self, data: Vec<u8>) -> ScriptArray {
        let ptr = self.new_array();
        let before = self.arrays[ptr].storage.retained_bytes();
        {
            let array_data = &mut self.arrays[ptr];
            array_data.tag.set_dirty();
            array_data.storage = ScriptArrayStorage::U8(data);
        }
        self.note_array_storage_growth(ptr, before);
        ptr
    }

    /// Mutates one array storage value while preserving aggregate heap
    /// accounting. Normal VM and adapter conversion paths should prefer this
    /// over [`Self::array_mut`].
    pub(crate) fn array_mut_with<R, F: FnOnce(&mut ScriptArrayStorage) -> R>(
        &mut self,
        array: ScriptArray,
        trap: ScriptTrap,
        cb: F,
    ) -> Option<R> {
        let before = self.arrays[array].storage.retained_bytes();
        let result = {
            let array_data = &mut self.arrays[array];
            if array_data.tag.is_immutable() {
                script_err_immutable!(trap, "array is immutable");
                return None;
            }
            array_data.tag.set_dirty();
            cb(&mut array_data.storage)
        };
        self.note_array_storage_growth(array, before);
        Some(result)
    }

    /// Returns direct mutable access for trusted raw VM hosts.
    ///
    /// This cannot observe capacity changes after the borrow escapes. A host
    /// that uses it while a heap cap is active must call
    /// [`Self::reconcile_heap_bytes`] before it re-enters untrusted script.
    /// Splash's normal VM paths use accounting-aware helpers instead.
    pub fn array_mut(
        &mut self,
        array: ScriptArray,
        trap: ScriptTrap,
    ) -> Option<&mut ScriptArrayStorage> {
        let array = &mut self.arrays[array];
        if array.tag.is_immutable() {
            script_err_immutable!(trap, "array is immutable");
            return None;
        }
        array.tag.set_dirty();
        Some(&mut array.storage)
    }

    pub fn array_mut_self_with<R, F: FnOnce(&mut Self, &ScriptArrayStorage) -> R>(
        &mut self,
        array: ScriptArray,
        cb: F,
    ) -> R {
        let mut storage = ScriptArrayStorage::ScriptValue(Default::default());
        std::mem::swap(&mut self.arrays[array].storage, &mut storage);
        let r = cb(self, &storage);
        std::mem::swap(&mut self.arrays[array].storage, &mut storage);
        r
    }

    pub fn array_mut_mut_self_with<R, F: FnOnce(&mut Self, &mut ScriptArrayStorage) -> R>(
        &mut self,
        array: ScriptArray,
        cb: F,
    ) -> R {
        let before = self.arrays[array].storage.retained_bytes();
        let mut storage = ScriptArrayStorage::ScriptValue(Default::default());
        std::mem::swap(&mut self.arrays[array].storage, &mut storage);
        let r = cb(self, &mut storage);
        std::mem::swap(&mut self.arrays[array].storage, &mut storage);
        self.note_array_storage_growth(array, before);
        r
    }

    pub fn array_remove(
        &mut self,
        array: ScriptArray,
        index: usize,
        trap: ScriptTrap,
    ) -> ScriptValue {
        let array = &mut self.arrays[array];
        if array.tag.is_immutable() {
            return script_err_immutable!(trap, "array is immutable");
        }
        array.tag.set_dirty();
        if index >= array.storage.len() {
            return script_err_out_of_bounds!(
                trap,
                "array remove index {} out of bounds (len={})",
                index,
                array.storage.len()
            );
        }
        array.storage.remove(index)
    }

    pub fn array_pop(&mut self, array: ScriptArray, trap: ScriptTrap) -> ScriptValue {
        let array = &mut self.arrays[array];
        if array.tag.is_immutable() {
            return script_err_immutable!(trap, "array is immutable");
        }
        if let Some(value) = array.storage.pop() {
            array.tag.set_dirty();
            value
        } else {
            script_err_out_of_bounds!(trap, "array pop on empty array")
        }
    }

    pub fn array_clear(&mut self, array: ScriptArray, trap: ScriptTrap) {
        let array = &mut self.arrays[array];
        if array.tag.is_immutable() {
            script_err_immutable!(trap, "array is immutable");
            return;
        }
        if array.storage.len() != 0 {
            array.storage.clear();
            array.tag.set_dirty();
        }
    }

    pub fn array_index(&self, array: ScriptArray, index: usize, trap: ScriptTrap) -> ScriptValue {
        let storage = &self.arrays[array].storage;
        if let Some(value) = storage.index(index) {
            return value;
        } else {
            script_err_out_of_bounds!(
                trap,
                "array index {} out of bounds (len={})",
                index,
                storage.len()
            )
        }
    }

    pub fn array_index_unchecked(&self, array: ScriptArray, index: usize) -> ScriptValue {
        if let Some(value) = self.arrays[array].storage.index(index) {
            return value;
        } else {
            NIL
        }
    }

    pub fn set_array_index(
        &mut self,
        array: ScriptArray,
        index: usize,
        value: ScriptValue,
        trap: ScriptTrap,
    ) -> ScriptValue {
        if self.arrays[array].tag.is_immutable() {
            return script_err_immutable!(trap, "array is immutable");
        }
        let Some(requested_len) = index.checked_add(1) else {
            self.can_grow_heap_by(None);
            return NIL;
        };
        let Some(before) = self.prepare_array_storage_growth(array, requested_len) else {
            return NIL;
        };
        {
            let array_data = &mut self.arrays[array];
            array_data.tag.set_dirty();
            array_data.storage.set_index(index, value);
        }
        self.note_array_storage_growth(array, before);
        NIL
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::array::ScriptArrayStorage;

    #[test]
    fn reused_array_slot_resets_to_script_value_storage() {
        let mut heap = ScriptHeap::default();

        let typed_array = heap.new_array_from_vec_u8(vec![1, 2, 3, 4]);
        let index = typed_array.index() as usize;

        // Simulate GC sweep/free for this slot.
        heap.arrays[typed_array].clear();
        heap.arrays.free_slot(typed_array.index());
        let new_gen = heap.arrays.generation(index);
        heap.arrays_free
            .push(ScriptArray::new(typed_array.index(), new_gen));

        let reused = heap.new_array();
        assert_eq!(reused.index(), typed_array.index());
        assert!(matches!(
            heap.arrays[reused].storage,
            ScriptArrayStorage::ScriptValue(_)
        ));
        assert_eq!(heap.array_len(reused), 0);
    }
}
