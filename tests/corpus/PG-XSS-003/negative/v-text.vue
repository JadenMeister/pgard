<!-- corpus: expect=none -->
<template>
  <span v-text="label"></span>
</template>
<script setup>
defineProps({ label: String });
</script>
